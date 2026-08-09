use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    path::{Path, PathBuf},
};

use ml_kem::EncapsulationKey1024;
use sha3::{Digest, Sha3_512};
use thiserror::Error;

use crate::{
    csemlk03::{self, ContentParametersData, Header, Manifest, Metadata, SignatureRecord},
    content_crypto::{self, ContentContext},
    key_id, metadata_crypto, mldsa, owner_envelope,
};

#[derive(Debug, Clone)]
pub struct EncryptV3Request {
    pub input_path: PathBuf,
    pub output_directory: PathBuf,
    pub original_file_name: String,
    pub mime_type: String,
    pub device_id: [u8; 16],
    pub revision: u64,
    pub previous_manifest_hash: [u8; 64],
    pub created_at_unix_millis: i64,
    pub modified_at_unix_millis: i64,
}

pub struct V3EncryptionKeys<'a> {
    pub encryption_public_key: &'a EncapsulationKey1024,
    pub signing_private_seed: &'a [u8],
    pub signing_public_key: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptV3Artifacts {
    pub client_file_id: [u8; 16],
    pub container_path: PathBuf,
    pub manifest_path: PathBuf,
    pub signature_path: PathBuf,
    pub container_hash: [u8; 64],
    pub container_size: u64,
    pub encryption_key_id: [u8; 32],
    pub signing_key_id: [u8; 32],
    pub revision: u64,
}

#[derive(Debug, Error)]
pub enum V3ArtifactError {
    #[error("input path is not a regular file")]
    InvalidInput,
    #[error("output artifact already exists: {0}")]
    OutputExists(PathBuf),
    #[error("secure random generation failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("CSEMLK03 format failed: {0}")]
    Format(#[from] csemlk03::FormatError),
    #[error("owner envelope failed: {0}")]
    OwnerEnvelope(#[from] owner_envelope::OwnerEnvelopeError),
    #[error("metadata encryption failed: {0}")]
    Metadata(#[from] metadata_crypto::MetadataCryptoError),
    #[error("content encryption failed: {0}")]
    Content(#[from] content_crypto::ContentCryptoError),
    #[error("manifest signing failed: {0}")]
    Signing(#[from] mldsa::MlDsaError),
    #[error("signing public key does not match its private seed")]
    SigningKeyMismatch,
    #[error("container size does not match the CSEMLK03 layout")]
    ContainerSizeMismatch,
}

pub fn encrypt_file_v3(
    request: &EncryptV3Request,
    keys: &V3EncryptionKeys<'_>,
) -> Result<EncryptV3Artifacts, V3ArtifactError> {
    let input_metadata = fs::metadata(&request.input_path)?;
    if !input_metadata.is_file() {
        return Err(V3ArtifactError::InvalidInput);
    }
    fs::create_dir_all(&request.output_directory)?;

    let exact_plaintext_size = input_metadata.len();
    let chunk_count = content_crypto::chunk_count(exact_plaintext_size)?;
    let client_file_id = random_uuid_bytes()?;
    let basename = format_uuid(&client_file_id);
    let paths = ArtifactPaths::new(&request.output_directory, &basename);
    paths.reject_existing()?;

    let result = (|| {
        let wrapped = owner_envelope::wrap_for_owner(
            keys.encryption_public_key,
            &client_file_id,
        )?;
        let (owner_envelope, file_master_key) = wrapped.into_parts();

        let mut file_kdf_salt = [0u8; 32];
        let mut content_nonce_prefix = [0u8; 8];
        getrandom::fill(&mut file_kdf_salt)?;
        getrandom::fill(&mut content_nonce_prefix)?;
        let content_parameters = ContentParametersData {
            client_file_id,
            file_kdf_salt,
            content_nonce_prefix,
        };
        let metadata = Metadata {
            client_file_id,
            revision: request.revision,
            exact_plaintext_size,
            created_at_unix_millis: request.created_at_unix_millis,
            modified_at_unix_millis: request.modified_at_unix_millis,
            filename: request.original_file_name.clone(),
            mime_type: request.mime_type.clone(),
        };
        let encrypted_metadata = metadata_crypto::encrypt_metadata(
            &file_master_key,
            chunk_count,
            &content_parameters,
            &owner_envelope,
            &metadata,
        )?;
        let header = Header {
            chunk_count,
            content_parameters,
            owner_envelope,
            encrypted_metadata: encrypted_metadata.encrypted_metadata,
        };
        metadata_crypto::verify_header_context(&header, &encrypted_metadata.header_context)?;
        let header_bytes = header.encode()?;

        let mut input = BufReader::new(File::open(&request.input_path)?);
        let mut container = create_new(&paths.container_temp)?;
        container.write_all(&header_bytes)?;
        content_crypto::encrypt_content(
            &mut input,
            &mut container,
            exact_plaintext_size,
            &ContentContext {
                file_master_key: &file_master_key,
                file_kdf_salt: &header.content_parameters.file_kdf_salt,
                client_file_id: &client_file_id,
                content_nonce_prefix: &header.content_parameters.content_nonce_prefix,
                exact_header_bytes: &header_bytes,
            },
        )?;
        container.flush()?;
        container.sync_all()?;
        drop(container);

        let container_size = fs::metadata(&paths.container_temp)?.len();
        let expected_size = csemlk03::expected_container_size(header_bytes.len(), chunk_count)?;
        if container_size != expected_size {
            return Err(V3ArtifactError::ContainerSizeMismatch);
        }
        let container_hash = sha3_512_file(&paths.container_temp)?;
        let encryption_key_id = header.owner_envelope.recipient_encryption_key_id;
        let signing_key_id = key_id::from_public_key(keys.signing_public_key);

        let manifest = Manifest {
            client_file_id,
            revision: request.revision,
            container_size,
            container_hash,
            owner_encryption_key_id: encryption_key_id,
            signing_key_id,
            device_id: request.device_id,
            created_at_unix_millis: request.created_at_unix_millis,
            previous_manifest_hash: request.previous_manifest_hash,
        };
        let manifest_bytes = manifest.encode()?;
        let signed_message = csemlk03::manifest_signing_message(&manifest_bytes)?;
        let signature = mldsa::sign_mldsa87(keys.signing_private_seed, &signed_message)?;
        mldsa::verify_mldsa87(keys.signing_public_key, &signed_message, &signature)
            .map_err(|_| V3ArtifactError::SigningKeyMismatch)?;
        let signature_record = SignatureRecord {
            signing_key_id,
            signature: signature.to_vec(),
        }.encode()?;

        write_new_synced(&paths.manifest_temp, &manifest_bytes)?;
        write_new_synced(&paths.signature_temp, &signature_record)?;
        paths.commit()?;

        Ok(EncryptV3Artifacts {
            client_file_id,
            container_path: paths.container_final.clone(),
            manifest_path: paths.manifest_final.clone(),
            signature_path: paths.signature_final.clone(),
            container_hash,
            container_size,
            encryption_key_id,
            signing_key_id,
            revision: request.revision,
        })
    })();

    if result.is_err() {
        paths.cleanup_temporary();
    }
    result
}

fn random_uuid_bytes() -> Result<[u8; 16], getrandom::Error> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(bytes)
}

fn format_uuid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

pub fn format_uuid_public(bytes: &[u8; 16]) -> String { format_uuid(bytes) }

fn sha3_512_file(path: &Path) -> Result<[u8; 64], std::io::Error> {
    let mut input = BufReader::new(File::open(path)?);
    let mut digest = Sha3_512::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 { break; }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
}

fn create_new(path: &Path) -> Result<File, std::io::Error> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut file = create_new(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()
}

struct ArtifactPaths {
    container_temp: PathBuf, manifest_temp: PathBuf, signature_temp: PathBuf,
    container_final: PathBuf, manifest_final: PathBuf, signature_final: PathBuf,
}

impl ArtifactPaths {
    fn new(directory: &Path, basename: &str) -> Self {
        Self {
            container_temp: directory.join(format!(".{basename}.fdcse.tmp")),
            manifest_temp: directory.join(format!(".{basename}.fdmanifest.tmp")),
            signature_temp: directory.join(format!(".{basename}.fdsig.tmp")),
            container_final: directory.join(format!("{basename}.fdcse")),
            manifest_final: directory.join(format!("{basename}.fdmanifest")),
            signature_final: directory.join(format!("{basename}.fdsig")),
        }
    }
    fn reject_existing(&self) -> Result<(), V3ArtifactError> {
        for path in [&self.container_temp, &self.manifest_temp, &self.signature_temp,
            &self.container_final, &self.manifest_final, &self.signature_final] {
            if path.exists() { return Err(V3ArtifactError::OutputExists(path.clone())); }
        }
        Ok(())
    }
    fn commit(&self) -> Result<(), std::io::Error> {
        let mut committed: Vec<&Path> = Vec::new();
        for (temporary, final_path) in [
            (&self.container_temp, &self.container_final),
            (&self.manifest_temp, &self.manifest_final),
            (&self.signature_temp, &self.signature_final),
        ] {
            if let Err(error) = fs::rename(temporary, final_path) {
                for path in committed { let _ = fs::remove_file(path); }
                return Err(error);
            }
            committed.push(final_path);
        }
        Ok(())
    }
    fn cleanup_temporary(&self) {
        for path in [&self.container_temp, &self.manifest_temp, &self.signature_temp] {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use ml_kem::{MlKem1024, kem::Kem};

    #[test]
    fn complete_artifacts_verify_and_decrypt_to_original() {
        let test_id = format!("{}-{}", std::process::id(), random_uuid_bytes().unwrap()[0]);
        let directory = std::env::temp_dir().join(format!("fd-v3-artifacts-{test_id}"));
        fs::create_dir_all(&directory).unwrap();
        let input_path = directory.join("very-secret-original-name.txt");
        let plaintext: Vec<u8> = (0..(csemlk03::CHUNK_SIZE as usize + 37))
            .map(|index| (index % 251) as u8).collect();
        fs::write(&input_path, &plaintext).unwrap();

        let (decapsulation_key, encryption_public_key) = MlKem1024::generate_keypair();
        let signing = mldsa::generate_mldsa87_keypair();
        let artifacts = encrypt_file_v3(
            &EncryptV3Request {
                input_path: input_path.clone(), output_directory: directory.clone(),
                original_file_name: "very-secret-original-name.txt".into(),
                mime_type: "text/plain".into(), device_id: [0x77; 16], revision: 1,
                previous_manifest_hash: [0; 64], created_at_unix_millis: 1_700_000_000_000,
                modified_at_unix_millis: 1_700_000_001_000,
            },
            &V3EncryptionKeys {
                encryption_public_key: &encryption_public_key,
                signing_private_seed: signing.private_seed(),
                signing_public_key: signing.public_key(),
            },
        ).unwrap();

        for path in [&artifacts.container_path, &artifacts.manifest_path, &artifacts.signature_path] {
            assert!(path.is_file());
            assert!(!path.file_name().unwrap().to_string_lossy().contains("very-secret"));
        }
        assert_eq!(sha3_512_file(&artifacts.container_path).unwrap(), artifacts.container_hash);

        let manifest_bytes = fs::read(&artifacts.manifest_path).unwrap();
        let manifest = Manifest::parse(&manifest_bytes).unwrap();
        let signature_record = SignatureRecord::parse(&fs::read(&artifacts.signature_path).unwrap()).unwrap();
        assert_eq!(signature_record.signing_key_id, manifest.signing_key_id);
        mldsa::verify_mldsa87(
            signing.public_key(),
            &csemlk03::manifest_signing_message(&manifest_bytes).unwrap(),
            &signature_record.signature,
        ).unwrap();

        let container = fs::read(&artifacts.container_path).unwrap();
        assert_eq!(container.len() as u64, manifest.container_size);
        let header_length = u32::from_le_bytes(container[12..16].try_into().unwrap()) as usize;
        let header_bytes = &container[..header_length];
        let header = Header::parse(header_bytes).unwrap();
        assert_eq!(header.content_parameters.client_file_id, manifest.client_file_id);
        assert_eq!(header.owner_envelope.recipient_encryption_key_id, manifest.owner_encryption_key_id);

        let master_key = owner_envelope::unwrap_for_owner(
            &decapsulation_key, &manifest.client_file_id, csemlk03::SUITE_ID, &header.owner_envelope,
        ).unwrap();
        let context = metadata_crypto::MetadataHeaderContext {
            fixed_preamble: header_bytes[..32].try_into().unwrap(),
            content_parameters_section: csemlk03::encode_content_parameters_section(&header.content_parameters),
            owner_key_envelope_section: csemlk03::encode_owner_key_envelope_section(&header.owner_envelope).unwrap(),
        };
        let metadata = metadata_crypto::decrypt_metadata(
            &master_key, &header.content_parameters, &header.owner_envelope,
            &header.encrypted_metadata, &context,
        ).unwrap();
        assert_eq!(metadata.filename, "very-secret-original-name.txt");
        assert_eq!(metadata.exact_plaintext_size, plaintext.len() as u64);

        let mut recovered = Vec::new();
        content_crypto::decrypt_content(
            &mut Cursor::new(&container[header_length..]), &mut recovered,
            metadata.exact_plaintext_size, header.chunk_count,
            &ContentContext {
                file_master_key: &master_key,
                file_kdf_salt: &header.content_parameters.file_kdf_salt,
                client_file_id: &manifest.client_file_id,
                content_nonce_prefix: &header.content_parameters.content_nonce_prefix,
                exact_header_bytes: header_bytes,
            },
        ).unwrap();
        assert_eq!(recovered, plaintext);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn failure_does_not_leave_temporary_artifacts() {
        let directory = std::env::temp_dir().join(format!("fd-v3-failure-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let input = directory.join("input.txt"); fs::write(&input, b"content").unwrap();
        let (_, encryption_public_key) = MlKem1024::generate_keypair();
        let signing = mldsa::generate_mldsa87_keypair();
        let result = encrypt_file_v3(
            &EncryptV3Request { input_path: input, output_directory: directory.clone(),
                original_file_name: "../unsafe.txt".into(), mime_type: "text/plain".into(),
                device_id: [0; 16], revision: 1, previous_manifest_hash: [0; 64],
                created_at_unix_millis: 1, modified_at_unix_millis: 1 },
            &V3EncryptionKeys { encryption_public_key: &encryption_public_key,
                signing_private_seed: signing.private_seed(), signing_public_key: signing.public_key() },
        );
        assert!(result.is_err());
        assert!(!fs::read_dir(&directory).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().ends_with(".tmp")));
        fs::remove_dir_all(directory).unwrap();
    }
}
