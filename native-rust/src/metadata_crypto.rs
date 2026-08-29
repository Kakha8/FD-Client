use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Nonce, Payload},
};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    csemlk03::{
        self, ContentParametersData, EncryptedMetadataData, FIXED_HEADER_LENGTH,
        FormatError, Header, Metadata, OwnerKeyEnvelopeData,
    },
    kdf::{self, FILE_MASTER_KEY_LENGTH},
};

const METADATA_AAD_DOMAIN: &[u8] = b"FD-CSE-V3-METADATA\0";
const METADATA_NONCE_LENGTH: usize = 12;
const GCM_TAG_LENGTH: usize = 16;

#[derive(Debug, Error)]
pub enum MetadataCryptoError {
    #[error("CSEMLK03 format error: {0}")]
    Format(#[from] FormatError),
    #[error("metadata KDF failed: {0}")]
    Kdf(#[from] kdf::KdfError),
    #[error("secure random generation failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error("metadata client file ID does not match the content parameters")]
    FileIdMismatch,
    #[error("could not initialize metadata AES-256-GCM")]
    InvalidMetadataKey,
    #[error("metadata encryption failed")]
    EncryptionFailed,
    #[error("metadata authentication or decryption failed")]
    DecryptionFailed,
    #[error("metadata header bytes are inconsistent")]
    HeaderMismatch,
}

/// Exact public bytes needed both for metadata AAD and final header assembly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataHeaderContext {
    pub fixed_preamble: [u8; FIXED_HEADER_LENGTH],
    pub content_parameters_section: Vec<u8>,
    pub owner_key_envelope_section: Vec<u8>,
}

pub struct EncryptedMetadataResult {
    pub encrypted_metadata: EncryptedMetadataData,
    pub header_context: MetadataHeaderContext,
}

pub fn encrypt_metadata(
    file_master_key: &[u8; FILE_MASTER_KEY_LENGTH],
    chunk_count: u32,
    content_parameters: &ContentParametersData,
    owner_envelope: &OwnerKeyEnvelopeData,
    metadata: &Metadata,
) -> Result<EncryptedMetadataResult, MetadataCryptoError> {
    if metadata.client_file_id != content_parameters.client_file_id {
        return Err(MetadataCryptoError::FileIdMismatch);
    }

    let plaintext = Zeroizing::new(metadata.encode()?);
    let content_section = csemlk03::encode_content_parameters_section(content_parameters);
    let owner_section = csemlk03::encode_owner_key_envelope_section(owner_envelope)?;
    let ciphertext_length = plaintext.len().checked_add(GCM_TAG_LENGTH)
        .ok_or(FormatError::SizeOverflow)?;
    let encrypted_section_length = 8usize
        .checked_add(12).and_then(|v| v.checked_add(4))
        .and_then(|v| v.checked_add(ciphertext_length))
        .ok_or(FormatError::SizeOverflow)?;
    let total_header_length = FIXED_HEADER_LENGTH
        .checked_add(content_section.len())
        .and_then(|v| v.checked_add(owner_section.len()))
        .and_then(|v| v.checked_add(encrypted_section_length))
        .ok_or(FormatError::SizeOverflow)?;
    let fixed_preamble = csemlk03::encode_fixed_preamble(total_header_length, chunk_count)?;
    let context = MetadataHeaderContext {
        fixed_preamble,
        content_parameters_section: content_section,
        owner_key_envelope_section: owner_section,
    };

    let keys = kdf::derive_file_keys(
        file_master_key,
        &content_parameters.file_kdf_salt,
        &content_parameters.client_file_id,
    )?;
    let cipher = Aes256Gcm::new_from_slice(keys.metadata_key())
        .map_err(|_| MetadataCryptoError::InvalidMetadataKey)?;
    let mut metadata_nonce = [0u8; METADATA_NONCE_LENGTH];
    getrandom::fill(&mut metadata_nonce)?;
    let nonce = Nonce::<Aes256Gcm>::try_from(&metadata_nonce[..])
        .map_err(|_| MetadataCryptoError::EncryptionFailed)?;
    let aad = metadata_aad(&context);
    let ciphertext = cipher.encrypt(
        &nonce,
        Payload { msg: &plaintext, aad: &aad },
    ).map_err(|_| MetadataCryptoError::EncryptionFailed)?;

    Ok(EncryptedMetadataResult {
        encrypted_metadata: EncryptedMetadataData { metadata_nonce, ciphertext },
        header_context: context,
    })
}

pub fn decrypt_metadata(
    file_master_key: &[u8; FILE_MASTER_KEY_LENGTH],
    content_parameters: &ContentParametersData,
    owner_envelope: &OwnerKeyEnvelopeData,
    encrypted_metadata: &EncryptedMetadataData,
    context: &MetadataHeaderContext,
) -> Result<Metadata, MetadataCryptoError> {
    let expected_content = csemlk03::encode_content_parameters_section(content_parameters);
    let expected_owner = csemlk03::encode_owner_key_envelope_section(owner_envelope)?;
    if context.content_parameters_section != expected_content
        || context.owner_key_envelope_section != expected_owner
    {
        return Err(MetadataCryptoError::HeaderMismatch);
    }

    let keys = kdf::derive_file_keys(
        file_master_key,
        &content_parameters.file_kdf_salt,
        &content_parameters.client_file_id,
    )?;
    let cipher = Aes256Gcm::new_from_slice(keys.metadata_key())
        .map_err(|_| MetadataCryptoError::InvalidMetadataKey)?;
    let nonce = Nonce::<Aes256Gcm>::try_from(&encrypted_metadata.metadata_nonce[..])
        .map_err(|_| MetadataCryptoError::DecryptionFailed)?;
    let aad = metadata_aad(context);
    let plaintext = Zeroizing::new(cipher.decrypt(
        &nonce,
        Payload { msg: &encrypted_metadata.ciphertext, aad: &aad },
    ).map_err(|_| MetadataCryptoError::DecryptionFailed)?);
    let metadata = Metadata::parse(&plaintext)?;
    if metadata.client_file_id != content_parameters.client_file_id {
        return Err(MetadataCryptoError::FileIdMismatch);
    }
    Ok(metadata)
}

/// Asserts that independently assembled header bytes are identical to the AAD
/// context created before metadata encryption.
pub fn verify_header_context(
    header: &Header,
    context: &MetadataHeaderContext,
) -> Result<(), MetadataCryptoError> {
    let encoded = header.encode()?;
    let prefix_length = FIXED_HEADER_LENGTH
        + context.content_parameters_section.len()
        + context.owner_key_envelope_section.len();
    let expected = metadata_aad_bytes(context);
    if encoded.get(..prefix_length) != Some(expected.as_slice()) {
        return Err(MetadataCryptoError::HeaderMismatch);
    }
    Ok(())
}

fn metadata_aad(context: &MetadataHeaderContext) -> Zeroizing<Vec<u8>> {
    let header_bytes = metadata_aad_bytes(context);
    let mut aad = Zeroizing::new(Vec::with_capacity(METADATA_AAD_DOMAIN.len() + header_bytes.len()));
    aad.extend_from_slice(METADATA_AAD_DOMAIN);
    aad.extend_from_slice(&header_bytes);
    aad
}

fn metadata_aad_bytes(context: &MetadataHeaderContext) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(
        FIXED_HEADER_LENGTH
            + context.content_parameters_section.len()
            + context.owner_key_envelope_section.len(),
    );
    bytes.extend_from_slice(&context.fixed_preamble);
    bytes.extend_from_slice(&context.content_parameters_section);
    bytes.extend_from_slice(&context.owner_key_envelope_section);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::{MlKem1024, kem::Kem};
    use crate::owner_envelope;

    fn fixture() -> (
        Zeroizing<[u8; 32]>,
        ContentParametersData,
        OwnerKeyEnvelopeData,
        Metadata,
    ) {
        let (_, public_key) = MlKem1024::generate_keypair();
        let file_id = [0x11; 16];
        let wrapped = owner_envelope::wrap_for_owner(&public_key, &file_id).unwrap();
        let (owner, master_key) = wrapped.into_parts();
        let content = ContentParametersData {
            client_file_id: file_id,
            file_kdf_salt: [0x22; 32],
            content_nonce_prefix: [0x33; 8],
        };
        let metadata = Metadata {
            client_file_id: file_id,
            revision: 1,
            exact_plaintext_size: 123_456,
            created_at_unix_millis: 1_700_000_000_000,
            modified_at_unix_millis: 1_700_000_001_000,
            filename: "private-name.txt".into(),
            mime_type: "text/plain".into(),
        };
        (master_key, content, owner, metadata)
    }

    #[test]
    fn metadata_encrypts_decrypts_and_matches_final_header_prefix() {
        let (master, content, owner, metadata) = fixture();
        let result = encrypt_metadata(&master, 1, &content, &owner, &metadata).unwrap();
        let recovered = decrypt_metadata(
            &master, &content, &owner, &result.encrypted_metadata, &result.header_context,
        ).unwrap();
        assert_eq!(recovered, metadata);
        assert_eq!(recovered.filename, "private-name.txt");
        assert_eq!(recovered.exact_plaintext_size, 123_456);

        let header = Header {
            chunk_count: 1,
            content_parameters: content,
            owner_envelope: owner,
            encrypted_metadata: result.encrypted_metadata,
        };
        verify_header_context(&header, &result.header_context).unwrap();
    }

    #[test]
    fn metadata_tampering_and_wrong_master_key_are_rejected() {
        let (master, content, owner, metadata) = fixture();
        let result = encrypt_metadata(&master, 1, &content, &owner, &metadata).unwrap();

        let mut ciphertext = result.encrypted_metadata.clone(); ciphertext.ciphertext[0] ^= 1;
        assert!(matches!(decrypt_metadata(&master, &content, &owner, &ciphertext, &result.header_context), Err(MetadataCryptoError::DecryptionFailed)));
        let mut nonce = result.encrypted_metadata.clone(); nonce.metadata_nonce[0] ^= 1;
        assert!(matches!(decrypt_metadata(&master, &content, &owner, &nonce, &result.header_context), Err(MetadataCryptoError::DecryptionFailed)));
        let wrong_master = [0xAA; 32];
        assert!(matches!(decrypt_metadata(&wrong_master, &content, &owner, &result.encrypted_metadata, &result.header_context), Err(MetadataCryptoError::DecryptionFailed)));
    }

    #[test]
    fn modifications_to_each_aad_component_are_rejected() {
        let (master, content, owner, metadata) = fixture();
        let result = encrypt_metadata(&master, 1, &content, &owner, &metadata).unwrap();

        let mut preamble = result.header_context.clone(); preamble.fixed_preamble[0] ^= 1;
        assert!(matches!(decrypt_metadata(&master, &content, &owner, &result.encrypted_metadata, &preamble), Err(MetadataCryptoError::DecryptionFailed)));

        let mut content_bytes = result.header_context.clone(); content_bytes.content_parameters_section[8] ^= 1;
        assert!(matches!(decrypt_metadata(&master, &content, &owner, &result.encrypted_metadata, &content_bytes), Err(MetadataCryptoError::HeaderMismatch)));

        let mut owner_bytes = result.header_context.clone(); owner_bytes.owner_key_envelope_section[8] ^= 1;
        assert!(matches!(decrypt_metadata(&master, &content, &owner, &result.encrypted_metadata, &owner_bytes), Err(MetadataCryptoError::HeaderMismatch)));
    }

    #[test]
    fn encryption_uses_fresh_nonce_and_rejects_mismatched_or_unsafe_metadata() {
        let (master, content, owner, metadata) = fixture();
        let first = encrypt_metadata(&master, 1, &content, &owner, &metadata).unwrap();
        let second = encrypt_metadata(&master, 1, &content, &owner, &metadata).unwrap();
        assert_ne!(first.encrypted_metadata.metadata_nonce, second.encrypted_metadata.metadata_nonce);
        assert_ne!(first.encrypted_metadata.ciphertext, second.encrypted_metadata.ciphertext);

        let mut mismatched = metadata.clone(); mismatched.client_file_id[0] ^= 1;
        assert!(matches!(encrypt_metadata(&master, 1, &content, &owner, &mismatched), Err(MetadataCryptoError::FileIdMismatch)));
        let mut unsafe_name = metadata; unsafe_name.filename = "../secret.txt".into();
        assert!(matches!(encrypt_metadata(&master, 1, &content, &owner, &unsafe_name), Err(MetadataCryptoError::Format(FormatError::UnsafeFilename))));
    }
}
