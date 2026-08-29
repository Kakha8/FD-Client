use thiserror::Error;
use ml_kem::kem::KeyExport;
use zeroize::Zeroizing;

use crate::{
    csemlk03::{self, FIXED_HEADER_LENGTH, Header, Manifest, SignatureRecord},
    key_id,
    metadata_crypto::{self, MetadataHeaderContext},
    metadata_view::PrivateMetadataView,
    mldsa,
    share_envelope,
};

const SHARE_GRANT_DOMAIN: &[u8] = b"FD-CSE-V3-SHARE-GRANT-V1\0";

#[derive(Debug, Error)]
pub enum ReceivedShareError {
    #[error("invalid CSEMLK03 data: {0}")]
    Format(#[from] csemlk03::FormatError),
    #[error("share or manifest signature is invalid: {0}")]
    Signature(#[from] mldsa::MlDsaError),
    #[error("recipient envelope could not be opened: {0}")]
    Envelope(#[from] share_envelope::ShareEnvelopeError),
    #[error("encrypted metadata could not be opened: {0}")]
    Metadata(#[from] metadata_crypto::MetadataCryptoError),
    #[error("received-share fields do not describe the same artifact")]
    Mismatch,
}

pub struct ReceivedShareRequest<'a> {
    pub envelope_package: &'a [u8],
    pub owner_share_signature: &'a [u8],
    pub owner_signing_key_id: &'a [u8],
    pub owner_signing_public_key: &'a [u8],
    pub manifest: &'a [u8],
    pub file_signature: &'a [u8],
    pub encrypted_header: &'a [u8],
    pub expected_share_id: [u8; 16],
    pub expected_recipient_account_id: [u8; 16],
    pub expected_client_file_id: [u8; 16],
    pub expected_revision: u64,
}

pub struct OpenedReceivedShare {
    pub view: PrivateMetadataView,
    pub master_key: Zeroizing<[u8; crate::kdf::FILE_MASTER_KEY_LENGTH]>,
    pub header: Header,
}

pub fn decrypt_received_metadata(
    request: &ReceivedShareRequest<'_>,
    recipient_private_key: &ml_kem::DecapsulationKey1024,
) -> Result<PrivateMetadataView, ReceivedShareError> {
    Ok(open_received_metadata(request, recipient_private_key)?.view)
}

pub fn open_received_metadata(
    request: &ReceivedShareRequest<'_>,
    recipient_private_key: &ml_kem::DecapsulationKey1024,
) -> Result<OpenedReceivedShare, ReceivedShareError> {
    let actual_owner_key_id = key_id::from_public_key(request.owner_signing_public_key);
    if request.owner_signing_key_id != actual_owner_key_id.as_slice() {
        return Err(ReceivedShareError::Mismatch);
    }

    let mut grant_message = Vec::with_capacity(
        SHARE_GRANT_DOMAIN.len() + request.envelope_package.len(),
    );
    grant_message.extend_from_slice(SHARE_GRANT_DOMAIN);
    grant_message.extend_from_slice(request.envelope_package);
    mldsa::verify_mldsa87(
        request.owner_signing_public_key,
        &grant_message,
        request.owner_share_signature,
    )?;

    let (share_context, recipient_envelope) =
        share_envelope::decode_package(request.envelope_package)?;
    if share_context.share_id != request.expected_share_id
        || share_context.recipient_account_id != request.expected_recipient_account_id
        || share_context.client_file_id != request.expected_client_file_id
        || share_context.revision != request.expected_revision
    {
        return Err(ReceivedShareError::Mismatch);
    }

    let recipient_public = recipient_private_key.encapsulation_key().to_bytes();
    if key_id::from_public_key(recipient_public.as_slice())
        != share_context.recipient_encryption_key_id
    {
        return Err(ReceivedShareError::Mismatch);
    }

    let manifest = Manifest::parse(request.manifest)?;
    let signature = SignatureRecord::parse(request.file_signature)?;
    if manifest.client_file_id != share_context.client_file_id
        || manifest.revision != share_context.revision
        || manifest.container_hash != share_context.container_hash
        || manifest.signing_key_id != actual_owner_key_id
        || signature.signing_key_id != actual_owner_key_id
    {
        return Err(ReceivedShareError::Mismatch);
    }
    mldsa::verify_mldsa87(
        request.owner_signing_public_key,
        &csemlk03::manifest_signing_message(request.manifest)?,
        &signature.signature,
    )?;

    let master_key = share_envelope::unwrap_for_recipient(
        recipient_private_key,
        &share_context,
        &recipient_envelope,
    )?;
    let header = Header::parse(request.encrypted_header)?;
    if header.content_parameters.client_file_id != manifest.client_file_id {
        return Err(ReceivedShareError::Mismatch);
    }

    let content_section = csemlk03::encode_content_parameters_section(&header.content_parameters);
    let owner_section = csemlk03::encode_owner_key_envelope_section(&header.owner_envelope)?;
    let prefix_end = FIXED_HEADER_LENGTH + content_section.len() + owner_section.len();
    if request.encrypted_header.get(FIXED_HEADER_LENGTH..FIXED_HEADER_LENGTH + content_section.len())
        != Some(content_section.as_slice())
        || request.encrypted_header.get(FIXED_HEADER_LENGTH + content_section.len()..prefix_end)
            != Some(owner_section.as_slice())
    {
        return Err(ReceivedShareError::Mismatch);
    }

    let metadata_context = MetadataHeaderContext {
        fixed_preamble: request.encrypted_header[..FIXED_HEADER_LENGTH]
            .try_into()
            .map_err(|_| ReceivedShareError::Mismatch)?,
        content_parameters_section: content_section,
        owner_key_envelope_section: owner_section,
    };
    let metadata = metadata_crypto::decrypt_metadata(
        &master_key,
        &header.content_parameters,
        &header.owner_envelope,
        &header.encrypted_metadata,
        &metadata_context,
    )?;
    if metadata.client_file_id != manifest.client_file_id
        || metadata.revision != manifest.revision
    {
        return Err(ReceivedShareError::Mismatch);
    }

    Ok(OpenedReceivedShare {
        view: PrivateMetadataView {
            client_file_id: crate::v3_artifacts::format_uuid_public(&metadata.client_file_id),
            filename: metadata.filename,
            mime_type: metadata.mime_type,
            exact_plaintext_size: metadata.exact_plaintext_size,
            created_at_unix_millis: metadata.created_at_unix_millis,
            modified_at_unix_millis: metadata.modified_at_unix_millis,
            revision: metadata.revision,
        },
        master_key,
        header,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        mldsa,
        share_artifacts::{self, CreateRecipientEnvelopeRequest, OwnerShareKeys},
        v3_artifacts::{self, EncryptV3Request, V3EncryptionKeys},
    };
    use ml_kem::{MlKem1024, kem::Kem};
    use std::{fs, io::Read};

    #[test]
    fn verifies_share_and_decrypts_recipient_metadata() {
        let directory = std::env::temp_dir().join(format!(
            "fd-received-share-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                .unwrap().as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        let input = directory.join("shared-secret.txt");
        fs::write(&input, b"received share verification").unwrap();

        let (owner_private, owner_public) = MlKem1024::generate_keypair();
        let owner_signing = mldsa::generate_mldsa87_keypair();
        let artifacts = v3_artifacts::encrypt_file_v3(
            &EncryptV3Request {
                input_path: input,
                output_directory: directory.clone(),
                original_file_name: "shared-secret.txt".into(),
                mime_type: "text/plain".into(),
                device_id: [0x33; 16],
                client_file_id: None,
                revision: 1,
                previous_manifest_hash: [0; 64],
                created_at_unix_millis: 10,
                modified_at_unix_millis: 20,
            },
            &V3EncryptionKeys {
                encryption_public_key: &owner_public,
                signing_private_seed: owner_signing.private_seed(),
                signing_public_key: owner_signing.public_key(),
            },
        ).unwrap();
        let (recipient_private, recipient_public) = MlKem1024::generate_keypair();
        let package = share_artifacts::create_recipient_envelope_package(
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
        ).unwrap();
        let (context, _) = share_envelope::decode_package(&package).unwrap();
        let mut grant = SHARE_GRANT_DOMAIN.to_vec();
        grant.extend_from_slice(&package);
        let share_signature = mldsa::sign_mldsa87(owner_signing.private_seed(), &grant).unwrap();
        let manifest = fs::read(&artifacts.manifest_path).unwrap();
        let file_signature = fs::read(&artifacts.signature_path).unwrap();
        let mut container = fs::File::open(&artifacts.container_path).unwrap();
        let mut preamble = [0u8; FIXED_HEADER_LENGTH];
        container.read_exact(&mut preamble).unwrap();
        let header_length = u32::from_le_bytes(preamble[12..16].try_into().unwrap()) as usize;
        let mut header = vec![0u8; header_length];
        header[..FIXED_HEADER_LENGTH].copy_from_slice(&preamble);
        container.read_exact(&mut header[FIXED_HEADER_LENGTH..]).unwrap();
        let owner_key_id = key_id::from_public_key(owner_signing.public_key());

        let request = ReceivedShareRequest {
            envelope_package: &package,
            owner_share_signature: &share_signature,
            owner_signing_key_id: &owner_key_id,
            owner_signing_public_key: owner_signing.public_key(),
            manifest: &manifest,
            file_signature: &file_signature,
            encrypted_header: &header,
            expected_share_id: context.share_id,
            expected_recipient_account_id: context.recipient_account_id,
            expected_client_file_id: context.client_file_id,
            expected_revision: context.revision,
        };
        let view = decrypt_received_metadata(&request, &recipient_private).unwrap();
        assert_eq!(view.filename, "shared-secret.txt");
        assert_eq!(view.revision, 1);

        let wrong_recipient = ReceivedShareRequest {
            expected_recipient_account_id: [0x44; 16],
            ..request
        };
        assert!(matches!(
            decrypt_received_metadata(&wrong_recipient, &recipient_private),
            Err(ReceivedShareError::Mismatch)
        ));
        fs::remove_dir_all(directory).unwrap();
    }
}
