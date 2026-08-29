use ml_kem::{DecapsulationKey1024, EncapsulationKey1024, kem::KeyExport};
use sha3::{Digest, Sha3_512};
use std::{
    fs::{self, File},
    io::{BufReader, Read},
    path::Path,
};
use thiserror::Error;

use crate::{
    csemlk03::{self, FIXED_HEADER_LENGTH, Header, Manifest, SignatureRecord},
    key_id, mldsa, owner_envelope,
    share_envelope::{self, PERMISSION_READ, ShareEnvelopeContext},
};

#[derive(Debug, Error)]
pub enum ShareArtifactError {
    #[error("could not read Lockbox artifacts: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid Lockbox v3 artifact: {0}")]
    Format(#[from] csemlk03::FormatError),
    #[error("manifest signature is invalid: {0}")]
    Signature(#[from] mldsa::MlDsaError),
    #[error("owner envelope could not be opened: {0}")]
    OwnerEnvelope(#[from] owner_envelope::OwnerEnvelopeError),
    #[error("recipient envelope could not be created: {0}")]
    ShareEnvelope(#[from] share_envelope::ShareEnvelopeError),
    #[error("manifest, container, signature, or local key does not match")]
    Mismatch,
    #[error("container header length is invalid")]
    InvalidHeaderLength,
    #[error("secure share ID generation failed")]
    Random,
}

pub struct CreateRecipientEnvelopeRequest<'a> {
    pub container_path: &'a Path,
    pub manifest_path: &'a Path,
    pub signature_path: &'a Path,
    pub owner_account_id: [u8; 16],
    pub recipient_account_id: [u8; 16],
    pub recipient_public_key: &'a EncapsulationKey1024,
    pub expires_at_unix_seconds: u64,
}

pub struct OwnerShareKeys<'a> {
    pub encryption_private_key: &'a DecapsulationKey1024,
    pub signing_public_key: &'a [u8],
}

pub fn create_recipient_envelope_package(
    request: &CreateRecipientEnvelopeRequest<'_>,
    owner_keys: &OwnerShareKeys<'_>,
) -> Result<Vec<u8>, ShareArtifactError> {
    let manifest_bytes = fs::read(request.manifest_path)?;
    let signature_bytes = fs::read(request.signature_path)?;
    let manifest = Manifest::parse(&manifest_bytes)?;
    let signature = SignatureRecord::parse(&signature_bytes)?;

    let actual_signing_key_id = key_id::from_public_key(owner_keys.signing_public_key);
    if actual_signing_key_id != manifest.signing_key_id
        || signature.signing_key_id != manifest.signing_key_id
    {
        return Err(ShareArtifactError::Mismatch);
    }

    mldsa::verify_mldsa87(
        owner_keys.signing_public_key,
        &csemlk03::manifest_signing_message(&manifest_bytes)?,
        &signature.signature,
    )?;

    let container_size = fs::metadata(request.container_path)?.len();
    if container_size != manifest.container_size
        || sha3_512_file(request.container_path)? != manifest.container_hash
    {
        return Err(ShareArtifactError::Mismatch);
    }

    let header_bytes = read_header(request.container_path)?;
    let header = Header::parse(&header_bytes)?;
    if header.content_parameters.client_file_id != manifest.client_file_id
        || header.owner_envelope.recipient_encryption_key_id != manifest.owner_encryption_key_id
        || csemlk03::expected_container_size(header_bytes.len(), header.chunk_count)?
            != manifest.container_size
    {
        return Err(ShareArtifactError::Mismatch);
    }

    let file_master_key = owner_envelope::unwrap_for_owner(
        owner_keys.encryption_private_key,
        &manifest.client_file_id,
        csemlk03::SUITE_ID,
        &header.owner_envelope,
    )?;

    let recipient_public_bytes = request.recipient_public_key.to_bytes();
    let recipient_key_id = key_id::from_public_key(recipient_public_bytes.as_slice());
    let context = ShareEnvelopeContext {
        share_id: random_uuid_bytes()?,
        client_file_id: manifest.client_file_id,
        revision: manifest.revision,
        container_hash: manifest.container_hash,
        owner_account_id: request.owner_account_id,
        recipient_account_id: request.recipient_account_id,
        recipient_encryption_key_id: recipient_key_id,
        permission: PERMISSION_READ,
        expires_at_unix_seconds: request.expires_at_unix_seconds,
    };
    let envelope = share_envelope::wrap_for_recipient(
        request.recipient_public_key,
        &file_master_key,
        &context,
    )?;

    Ok(share_envelope::encode_package(&context, &envelope)?)
}

fn read_header(path: &Path) -> Result<Vec<u8>, ShareArtifactError> {
    let mut input = BufReader::new(File::open(path)?);
    let mut preamble = [0u8; FIXED_HEADER_LENGTH];
    input.read_exact(&mut preamble)?;
    let total_length = u32::from_le_bytes(
        preamble[12..16]
            .try_into()
            .map_err(|_| ShareArtifactError::InvalidHeaderLength)?,
    ) as usize;

    if !(FIXED_HEADER_LENGTH..=csemlk03::MAX_HEADER_LENGTH).contains(&total_length) {
        return Err(ShareArtifactError::InvalidHeaderLength);
    }

    let mut header = vec![0u8; total_length];
    header[..FIXED_HEADER_LENGTH].copy_from_slice(&preamble);
    input.read_exact(&mut header[FIXED_HEADER_LENGTH..])?;
    Ok(header)
}

fn sha3_512_file(path: &Path) -> Result<[u8; 64], std::io::Error> {
    let mut input = BufReader::new(File::open(path)?);
    let mut digest = Sha3_512::new();
    let mut buffer = vec![0u8; 1024 * 1024];

    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }

    Ok(digest.finalize().into())
}

fn random_uuid_bytes() -> Result<[u8; 16], ShareArtifactError> {
    let mut value = [0u8; 16];
    getrandom::fill(&mut value).map_err(|_| ShareArtifactError::Random)?;
    value[6] = (value[6] & 0x0f) | 0x40;
    value[8] = (value[8] & 0x3f) | 0x80;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mldsa, share_envelope,
        v3_artifacts::{self, EncryptV3Request, V3EncryptionKeys},
    };
    use ml_kem::{MlKem1024, kem::Kem};
    use std::io::{Read, Seek, SeekFrom};

    #[test]
    fn verified_artifacts_are_rewrapped_for_recipient() {
        let directory = std::env::temp_dir().join(format!(
            "fd-share-envelope-{}-{}",
            std::process::id(),
            random_uuid_bytes().unwrap()[0]
        ));
        fs::create_dir_all(&directory).unwrap();
        let input = directory.join("secret.txt");
        fs::write(&input, b"share envelope integration test").unwrap();

        let (owner_private, owner_public) = MlKem1024::generate_keypair();
        let owner_signing = mldsa::generate_mldsa87_keypair();
        let artifacts = v3_artifacts::encrypt_file_v3(
            &EncryptV3Request {
                input_path: input,
                output_directory: directory.clone(),
                original_file_name: "secret.txt".into(),
                mime_type: "text/plain".into(),
                device_id: [0x55; 16],
                client_file_id: None,
                revision: 1,
                previous_manifest_hash: [0; 64],
                created_at_unix_millis: 1,
                modified_at_unix_millis: 1,
            },
            &V3EncryptionKeys {
                encryption_public_key: &owner_public,
                signing_private_seed: owner_signing.private_seed(),
                signing_public_key: owner_signing.public_key(),
            },
        )
        .unwrap();

        let (recipient_private, recipient_public) = MlKem1024::generate_keypair();
        let package = create_recipient_envelope_package(
            &CreateRecipientEnvelopeRequest {
                container_path: &artifacts.container_path,
                manifest_path: &artifacts.manifest_path,
                signature_path: &artifacts.signature_path,
                owner_account_id: [0x11; 16],
                recipient_account_id: [0x22; 16],
                recipient_public_key: &recipient_public,
                expires_at_unix_seconds: 0,
            },
            &OwnerShareKeys {
                encryption_private_key: &owner_private,
                signing_public_key: owner_signing.public_key(),
            },
        )
        .unwrap();
        let (context, recipient_envelope) = share_envelope::decode_package(&package).unwrap();
        let recipient_master_key =
            share_envelope::unwrap_for_recipient(&recipient_private, &context, &recipient_envelope)
                .unwrap();

        let mut container = File::open(&artifacts.container_path).unwrap();
        let mut preamble = [0u8; FIXED_HEADER_LENGTH];
        container.read_exact(&mut preamble).unwrap();
        let header_length = u32::from_le_bytes(preamble[12..16].try_into().unwrap()) as usize;
        container.seek(SeekFrom::Start(0)).unwrap();
        let mut header_bytes = vec![0u8; header_length];
        container.read_exact(&mut header_bytes).unwrap();
        let header = Header::parse(&header_bytes).unwrap();
        let owner_master_key = owner_envelope::unwrap_for_owner(
            &owner_private,
            &context.client_file_id,
            csemlk03::SUITE_ID,
            &header.owner_envelope,
        )
        .unwrap();

        assert_eq!(&recipient_master_key[..], &owner_master_key[..]);
        assert_eq!(context.client_file_id, artifacts.client_file_id);
        assert_eq!(context.container_hash, artifacts.container_hash);

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn generated_share_id_is_uuid_v4() {
        let uuid = random_uuid_bytes().unwrap();
        assert_eq!(uuid[6] >> 4, 4);
        assert_eq!(uuid[8] >> 6, 2);
    }
}
