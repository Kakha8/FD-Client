use sha3::{Digest, Sha3_512};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
};
use thiserror::Error;

use crate::{
    content_crypto::{self, ContentContext},
    csemlk03::{self, FIXED_HEADER_LENGTH, Manifest},
    metadata_view,
    received_share::{self, ReceivedShareRequest},
};

#[derive(Debug, Error)]
pub enum V3DecryptError {
    #[error("filesystem operation failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid CSEMLK03 data: {0}")]
    Format(#[from] csemlk03::FormatError),
    #[error("owned artifact verification failed: {0}")]
    Owned(#[from] metadata_view::PrivateMetadataError),
    #[error("received-share verification failed: {0}")]
    Shared(#[from] received_share::ReceivedShareError),
    #[error("content decryption failed: {0}")]
    Content(#[from] content_crypto::ContentCryptoError),
    #[error("container does not match the signed manifest")]
    ContainerMismatch,
    #[error("container header length is invalid")]
    InvalidHeader,
}

pub fn decrypt_owned_to(
    container_path: &Path,
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    output_path: &Path,
    signing_public_key: &[u8],
    encryption_private_key: &ml_kem::DecapsulationKey1024,
) -> Result<(), V3DecryptError> {
    let manifest = verify_container(container_path, manifest_bytes)?;
    let header_bytes = read_header(container_path)?;
    let opened = metadata_view::open_private_metadata(
        manifest_bytes, signature_bytes, &header_bytes,
        signing_public_key, encryption_private_key,
    )?;
    decrypt_content_to(container_path, output_path, &manifest, &header_bytes,
        &opened.header, &opened.master_key, opened.view.exact_plaintext_size)
}

pub fn decrypt_shared_to(
    container_path: &Path,
    output_path: &Path,
    request: &ReceivedShareRequest<'_>,
    recipient_private_key: &ml_kem::DecapsulationKey1024,
) -> Result<(), V3DecryptError> {
    let manifest = verify_container(container_path, request.manifest)?;
    let header_bytes = read_header(container_path)?;
    if header_bytes != request.encrypted_header {
        return Err(V3DecryptError::ContainerMismatch);
    }
    let opened = received_share::open_received_metadata(request, recipient_private_key)?;
    decrypt_content_to(container_path, output_path, &manifest, &header_bytes,
        &opened.header, &opened.master_key, opened.view.exact_plaintext_size)
}

fn verify_container(path: &Path, manifest_bytes: &[u8]) -> Result<Manifest, V3DecryptError> {
    let manifest = Manifest::parse(manifest_bytes)?;
    if fs::metadata(path)?.len() != manifest.container_size {
        return Err(V3DecryptError::ContainerMismatch);
    }
    let mut input = BufReader::new(File::open(path)?);
    let mut digest = Sha3_512::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 { break; }
        digest.update(&buffer[..count]);
    }
    let actual: [u8; 64] = digest.finalize().into();
    if actual != manifest.container_hash {
        return Err(V3DecryptError::ContainerMismatch);
    }
    Ok(manifest)
}

fn read_header(path: &Path) -> Result<Vec<u8>, V3DecryptError> {
    let mut input = BufReader::new(File::open(path)?);
    let mut preamble = [0u8; FIXED_HEADER_LENGTH];
    input.read_exact(&mut preamble)?;
    let length = u32::from_le_bytes(
        preamble[12..16].try_into().map_err(|_| V3DecryptError::InvalidHeader)?
    ) as usize;
    if !(FIXED_HEADER_LENGTH..=csemlk03::MAX_HEADER_LENGTH).contains(&length) {
        return Err(V3DecryptError::InvalidHeader);
    }
    let mut header = vec![0u8; length];
    header[..FIXED_HEADER_LENGTH].copy_from_slice(&preamble);
    input.read_exact(&mut header[FIXED_HEADER_LENGTH..])?;
    Ok(header)
}

fn decrypt_content_to(
    container_path: &Path,
    output_path: &Path,
    manifest: &Manifest,
    header_bytes: &[u8],
    header: &csemlk03::Header,
    master_key: &[u8; crate::kdf::FILE_MASTER_KEY_LENGTH],
    plaintext_size: u64,
) -> Result<(), V3DecryptError> {
    let output = OpenOptions::new().write(true).create_new(true).open(output_path)?;
    let result = (|| -> Result<(), V3DecryptError> {
        let mut input = BufReader::new(File::open(container_path)?);
        input.seek(SeekFrom::Start(header_bytes.len() as u64))?;
        let mut output = BufWriter::new(output);
        content_crypto::decrypt_content(
            &mut input,
            &mut output,
            plaintext_size,
            header.chunk_count,
            &ContentContext {
                file_master_key: master_key,
                file_kdf_salt: &header.content_parameters.file_kdf_salt,
                client_file_id: &manifest.client_file_id,
                content_nonce_prefix: &header.content_parameters.content_nonce_prefix,
                exact_header_bytes: header_bytes,
            },
        )?;
        output.flush()?;
        output.get_ref().sync_all()?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(output_path);
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        key_id, mldsa, share_artifacts,
        share_envelope,
        v3_artifacts::{self, EncryptV3Request, V3EncryptionKeys},
    };
    use ml_kem::{MlKem1024, kem::Kem};

    #[test]
    fn owned_and_received_share_export_exact_plaintext() {
        let directory = std::env::temp_dir().join(format!(
            "fd-v3-export-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .unwrap().as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        let plaintext: Vec<u8> = (0..(csemlk03::CHUNK_SIZE as usize + 73))
            .map(|index| (index % 251) as u8).collect();
        let input = directory.join("private.bin");
        fs::write(&input, &plaintext).unwrap();
        let (owner_private, owner_public) = MlKem1024::generate_keypair();
        let owner_signing = mldsa::generate_mldsa87_keypair();
        let artifacts = v3_artifacts::encrypt_file_v3(
            &EncryptV3Request {
                input_path: input,
                output_directory: directory.clone(),
                original_file_name: "private.bin".into(),
                mime_type: "application/octet-stream".into(),
                device_id: [0x55; 16], client_file_id: None, revision: 1,
                previous_manifest_hash: [0; 64],
                created_at_unix_millis: 1, modified_at_unix_millis: 2,
            },
            &V3EncryptionKeys {
                encryption_public_key: &owner_public,
                signing_private_seed: owner_signing.private_seed(),
                signing_public_key: owner_signing.public_key(),
            },
        ).unwrap();
        let manifest = fs::read(&artifacts.manifest_path).unwrap();
        let signature = fs::read(&artifacts.signature_path).unwrap();
        let owned_output = directory.join("owned-output.bin");
        decrypt_owned_to(
            &artifacts.container_path, &manifest, &signature, &owned_output,
            owner_signing.public_key(), &owner_private,
        ).unwrap();
        assert_eq!(fs::read(&owned_output).unwrap(), plaintext);

        let (recipient_private, recipient_public) = MlKem1024::generate_keypair();
        let package = share_artifacts::create_recipient_envelope_package(
            &share_artifacts::CreateRecipientEnvelopeRequest {
                container_path: &artifacts.container_path,
                manifest_path: &artifacts.manifest_path,
                signature_path: &artifacts.signature_path,
                owner_account_id: [0x11; 16], recipient_account_id: [0x22; 16],
                recipient_public_key: &recipient_public, expires_at_unix_seconds: 0,
            },
            &share_artifacts::OwnerShareKeys {
                encryption_private_key: &owner_private,
                signing_public_key: owner_signing.public_key(),
            },
        ).unwrap();
        let (context, _) = share_envelope::decode_package(&package).unwrap();
        let mut grant = b"FD-CSE-V3-SHARE-GRANT-V1\0".to_vec();
        grant.extend_from_slice(&package);
        let share_signature = mldsa::sign_mldsa87(owner_signing.private_seed(), &grant).unwrap();
        let header = read_header(&artifacts.container_path).unwrap();
        let owner_key_id = key_id::from_public_key(owner_signing.public_key());
        let request = ReceivedShareRequest {
            envelope_package: &package,
            owner_share_signature: &share_signature,
            owner_signing_key_id: &owner_key_id,
            owner_signing_public_key: owner_signing.public_key(),
            manifest: &manifest,
            file_signature: &signature,
            encrypted_header: &header,
            expected_share_id: context.share_id,
            expected_recipient_account_id: context.recipient_account_id,
            expected_client_file_id: context.client_file_id,
            expected_revision: context.revision,
        };
        let shared_output = directory.join("shared-output.bin");
        decrypt_shared_to(
            &artifacts.container_path, &shared_output, &request, &recipient_private,
        ).unwrap();
        assert_eq!(fs::read(&shared_output).unwrap(), plaintext);

        fs::remove_dir_all(directory).unwrap();
    }
}
