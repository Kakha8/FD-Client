use ml_kem::DecapsulationKey1024;
use serde::Serialize;
use thiserror::Error;

use crate::{
    csemlk03::{self, Header, Manifest, SignatureRecord, FIXED_HEADER_LENGTH, SUITE_ID},
    metadata_crypto::{self, MetadataHeaderContext},
    mldsa, owner_envelope,
};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateMetadataView {
    pub client_file_id: String,
    pub filename: String,
    pub mime_type: String,
    pub exact_plaintext_size: u64,
    pub created_at_unix_millis: i64,
    pub modified_at_unix_millis: i64,
    pub revision: u64,
}

#[derive(Debug, Error)]
pub enum PrivateMetadataError {
    #[error("invalid CSEMLK03 data: {0}")]
    Format(#[from] csemlk03::FormatError),
    #[error("manifest signature is invalid: {0}")]
    Signature(#[from] mldsa::MlDsaError),
    #[error("owner envelope could not be opened: {0}")]
    Envelope(#[from] owner_envelope::OwnerEnvelopeError),
    #[error("encrypted metadata could not be opened: {0}")]
    Metadata(#[from] metadata_crypto::MetadataCryptoError),
    #[error("manifest, signature, header, or local key does not match")]
    Mismatch,
}

pub fn decrypt_private_metadata(
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
    header_bytes: &[u8],
    signing_public_key: &[u8],
    encryption_private_key: &DecapsulationKey1024,
) -> Result<PrivateMetadataView, PrivateMetadataError> {
    let manifest = Manifest::parse(manifest_bytes)?;
    let signature = SignatureRecord::parse(signature_bytes)?;
    let signing_key_id = crate::key_id::from_public_key(signing_public_key);
    if signature.signing_key_id != manifest.signing_key_id
        || signing_key_id != manifest.signing_key_id
    {
        return Err(PrivateMetadataError::Mismatch);
    }
    mldsa::verify_mldsa87(
        signing_public_key,
        &csemlk03::manifest_signing_message(manifest_bytes)?,
        &signature.signature,
    )?;

    let header = Header::parse(header_bytes)?;
    if header.content_parameters.client_file_id != manifest.client_file_id
        || header.owner_envelope.recipient_encryption_key_id != manifest.owner_encryption_key_id
    {
        return Err(PrivateMetadataError::Mismatch);
    }
    let master_key = owner_envelope::unwrap_for_owner(
        encryption_private_key,
        &manifest.client_file_id,
        SUITE_ID,
        &header.owner_envelope,
    )?;
    let content_section = csemlk03::encode_content_parameters_section(&header.content_parameters);
    let owner_section = csemlk03::encode_owner_key_envelope_section(&header.owner_envelope)?;
    let prefix_end = FIXED_HEADER_LENGTH + content_section.len() + owner_section.len();
    if header_bytes.get(FIXED_HEADER_LENGTH..FIXED_HEADER_LENGTH + content_section.len())
        != Some(content_section.as_slice())
        || header_bytes.get(FIXED_HEADER_LENGTH + content_section.len()..prefix_end)
            != Some(owner_section.as_slice())
    {
        return Err(PrivateMetadataError::Mismatch);
    }
    let context = MetadataHeaderContext {
        fixed_preamble: header_bytes[..FIXED_HEADER_LENGTH]
            .try_into().map_err(|_| PrivateMetadataError::Mismatch)?,
        content_parameters_section: content_section,
        owner_key_envelope_section: owner_section,
    };
    let metadata = metadata_crypto::decrypt_metadata(
        &master_key,
        &header.content_parameters,
        &header.owner_envelope,
        &header.encrypted_metadata,
        &context,
    )?;
    if metadata.client_file_id != manifest.client_file_id
        || metadata.revision != manifest.revision
    {
        return Err(PrivateMetadataError::Mismatch);
    }
    Ok(PrivateMetadataView {
        client_file_id: crate::v3_artifacts::format_uuid_public(&metadata.client_file_id),
        filename: metadata.filename,
        mime_type: metadata.mime_type,
        exact_plaintext_size: metadata.exact_plaintext_size,
        created_at_unix_millis: metadata.created_at_unix_millis,
        modified_at_unix_millis: metadata.modified_at_unix_millis,
        revision: metadata.revision,
    })
}
