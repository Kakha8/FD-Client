use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Nonce, Payload},
};
use hkdf::Hkdf;
use ml_kem::{
    DecapsulationKey1024, EncapsulationKey1024,
    kem::{Decapsulate, Encapsulate, KeyExport},
};
use sha3::{Digest, Sha3_512};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    csemlk03::{ML_KEM_1024_CIPHERTEXT_LENGTH, SUITE_ID, WRAPPED_FILE_MASTER_KEY_LENGTH},
    kdf::FILE_MASTER_KEY_LENGTH,
    key_id,
};

pub const SHARE_ENVELOPE_VERSION: u16 = 1;
pub const SHARE_CONTEXT_LENGTH: usize = 182;
pub const SHARE_WRAP_SALT_LENGTH: usize = 32;
pub const SHARE_WRAP_NONCE_LENGTH: usize = 12;
pub const PERMISSION_READ: u16 = 1;
pub const SHARE_ENVELOPE_MAGIC: &[u8; 8] = b"FDSHENV1";
pub const SHARE_ENVELOPE_PACKAGE_LENGTH: usize = 8
    + SHARE_CONTEXT_LENGTH
    + SHARE_WRAP_SALT_LENGTH
    + SHARE_WRAP_NONCE_LENGTH
    + 4
    + 4
    + ML_KEM_1024_CIPHERTEXT_LENGTH
    + WRAPPED_FILE_MASTER_KEY_LENGTH;

const WRAP_KEY_DOMAIN: &[u8] = b"FD-CSE-V3-SHARE-WRAP-KEY-V1\0";
const WRAP_AAD_DOMAIN: &[u8] = b"FD-CSE-V3-SHARE-ENVELOPE-V1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareEnvelopeContext {
    pub share_id: [u8; 16],
    pub client_file_id: [u8; 16],
    pub revision: u64,
    pub container_hash: [u8; 64],
    pub owner_account_id: [u8; 16],
    pub recipient_account_id: [u8; 16],
    pub recipient_encryption_key_id: [u8; 32],
    pub permission: u16,
    pub expires_at_unix_seconds: u64,
}

impl ShareEnvelopeContext {
    pub fn encode(&self) -> Result<[u8; SHARE_CONTEXT_LENGTH], ShareEnvelopeError> {
        self.validate()?;

        let mut encoded = [0u8; SHARE_CONTEXT_LENGTH];
        let mut offset = 0;

        append(
            &mut encoded,
            &mut offset,
            &SHARE_ENVELOPE_VERSION.to_le_bytes(),
        );
        append(&mut encoded, &mut offset, &SUITE_ID.to_le_bytes());
        append(&mut encoded, &mut offset, &self.share_id);
        append(&mut encoded, &mut offset, &self.client_file_id);
        append(&mut encoded, &mut offset, &self.revision.to_le_bytes());
        append(&mut encoded, &mut offset, &self.container_hash);
        append(&mut encoded, &mut offset, &self.owner_account_id);
        append(&mut encoded, &mut offset, &self.recipient_account_id);
        append(&mut encoded, &mut offset, &self.recipient_encryption_key_id);
        append(&mut encoded, &mut offset, &self.permission.to_le_bytes());
        append(
            &mut encoded,
            &mut offset,
            &self.expires_at_unix_seconds.to_le_bytes(),
        );

        debug_assert_eq!(offset, SHARE_CONTEXT_LENGTH);
        Ok(encoded)
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, ShareEnvelopeError> {
        if encoded.len() != SHARE_CONTEXT_LENGTH
            || u16::from_le_bytes(encoded[0..2].try_into().unwrap()) != SHARE_ENVELOPE_VERSION
            || u16::from_le_bytes(encoded[2..4].try_into().unwrap()) != SUITE_ID
        {
            return Err(ShareEnvelopeError::InvalidContext);
        }

        let context = Self {
            share_id: encoded[4..20].try_into().unwrap(),
            client_file_id: encoded[20..36].try_into().unwrap(),
            revision: u64::from_le_bytes(encoded[36..44].try_into().unwrap()),
            container_hash: encoded[44..108].try_into().unwrap(),
            owner_account_id: encoded[108..124].try_into().unwrap(),
            recipient_account_id: encoded[124..140].try_into().unwrap(),
            recipient_encryption_key_id: encoded[140..172].try_into().unwrap(),
            permission: u16::from_le_bytes(encoded[172..174].try_into().unwrap()),
            expires_at_unix_seconds: u64::from_le_bytes(encoded[174..182].try_into().unwrap()),
        };
        context.validate()?;
        Ok(context)
    }

    fn validate(&self) -> Result<(), ShareEnvelopeError> {
        if self.share_id == [0; 16]
            || self.client_file_id == [0; 16]
            || self.revision == 0
            || self.container_hash == [0; 64]
            || self.owner_account_id == [0; 16]
            || self.recipient_account_id == [0; 16]
            || self.recipient_encryption_key_id == [0; 32]
            || self.permission != PERMISSION_READ
        {
            return Err(ShareEnvelopeError::InvalidContext);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecipientShareEnvelope {
    pub wrap_salt: [u8; SHARE_WRAP_SALT_LENGTH],
    pub wrap_nonce: [u8; SHARE_WRAP_NONCE_LENGTH],
    pub kem_ciphertext: Vec<u8>,
    pub wrapped_file_master_key: Vec<u8>,
}

pub fn encode_package(
    context: &ShareEnvelopeContext,
    envelope: &RecipientShareEnvelope,
) -> Result<Vec<u8>, ShareEnvelopeError> {
    let context_bytes = context.encode()?;

    if envelope.kem_ciphertext.len() != ML_KEM_1024_CIPHERTEXT_LENGTH {
        return Err(ShareEnvelopeError::InvalidKemCiphertext);
    }

    if envelope.wrapped_file_master_key.len() != WRAPPED_FILE_MASTER_KEY_LENGTH {
        return Err(ShareEnvelopeError::InvalidWrappedKey);
    }

    let mut encoded = Vec::with_capacity(SHARE_ENVELOPE_PACKAGE_LENGTH);
    encoded.extend_from_slice(SHARE_ENVELOPE_MAGIC);
    encoded.extend_from_slice(&context_bytes);
    encoded.extend_from_slice(&envelope.wrap_salt);
    encoded.extend_from_slice(&envelope.wrap_nonce);
    encoded.extend_from_slice(&(ML_KEM_1024_CIPHERTEXT_LENGTH as u32).to_le_bytes());
    encoded.extend_from_slice(&(WRAPPED_FILE_MASTER_KEY_LENGTH as u32).to_le_bytes());
    encoded.extend_from_slice(&envelope.kem_ciphertext);
    encoded.extend_from_slice(&envelope.wrapped_file_master_key);
    debug_assert_eq!(encoded.len(), SHARE_ENVELOPE_PACKAGE_LENGTH);
    Ok(encoded)
}

pub fn decode_package(
    encoded: &[u8],
) -> Result<(ShareEnvelopeContext, RecipientShareEnvelope), ShareEnvelopeError> {
    if encoded.len() != SHARE_ENVELOPE_PACKAGE_LENGTH
        || encoded.get(..8) != Some(SHARE_ENVELOPE_MAGIC.as_slice())
    {
        return Err(ShareEnvelopeError::InvalidPackage);
    }

    let context_end = 8 + SHARE_CONTEXT_LENGTH;
    let salt_end = context_end + SHARE_WRAP_SALT_LENGTH;
    let nonce_end = salt_end + SHARE_WRAP_NONCE_LENGTH;
    let kem_length =
        u32::from_le_bytes(encoded[nonce_end..nonce_end + 4].try_into().unwrap()) as usize;
    let wrapped_length =
        u32::from_le_bytes(encoded[nonce_end + 4..nonce_end + 8].try_into().unwrap()) as usize;

    if kem_length != ML_KEM_1024_CIPHERTEXT_LENGTH
        || wrapped_length != WRAPPED_FILE_MASTER_KEY_LENGTH
    {
        return Err(ShareEnvelopeError::InvalidPackage);
    }

    let payload = nonce_end + 8;
    let kem_end = payload + kem_length;
    let context = ShareEnvelopeContext::decode(&encoded[8..context_end])?;
    let envelope = RecipientShareEnvelope {
        wrap_salt: encoded[context_end..salt_end].try_into().unwrap(),
        wrap_nonce: encoded[salt_end..nonce_end].try_into().unwrap(),
        kem_ciphertext: encoded[payload..kem_end].to_vec(),
        wrapped_file_master_key: encoded[kem_end..].to_vec(),
    };
    Ok((context, envelope))
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ShareEnvelopeError {
    #[error("share envelope context is invalid")]
    InvalidContext,
    #[error("share envelope package is invalid")]
    InvalidPackage,
    #[error("recipient public key does not match the requested key ID")]
    RecipientKeyMismatch,
    #[error("secure random generation failed")]
    Random,
    #[error("share-envelope KDF failed")]
    Kdf,
    #[error("could not initialize AES-256-GCM")]
    InvalidWrappingKey,
    #[error("ML-KEM ciphertext has an invalid length")]
    InvalidKemCiphertext,
    #[error("wrapped file master key has an invalid length")]
    InvalidWrappedKey,
    #[error("file master key wrapping failed")]
    WrappingFailed,
    #[error("file master key authentication or unwrapping failed")]
    UnwrappingFailed,
}

pub fn wrap_for_recipient(
    recipient_public_key: &EncapsulationKey1024,
    file_master_key: &[u8; FILE_MASTER_KEY_LENGTH],
    context: &ShareEnvelopeContext,
) -> Result<RecipientShareEnvelope, ShareEnvelopeError> {
    let context_bytes = context.encode()?;
    let public_key_bytes = recipient_public_key.to_bytes();
    let actual_key_id = key_id::from_public_key(public_key_bytes.as_slice());

    if actual_key_id != context.recipient_encryption_key_id {
        return Err(ShareEnvelopeError::RecipientKeyMismatch);
    }

    let (kem_ciphertext, mut shared_secret) = recipient_public_key.encapsulate();
    let kem_ciphertext = kem_ciphertext.as_slice().to_vec();
    let mut wrap_salt = [0u8; SHARE_WRAP_SALT_LENGTH];
    let mut wrap_nonce = [0u8; SHARE_WRAP_NONCE_LENGTH];

    getrandom::fill(&mut wrap_salt).map_err(|_| ShareEnvelopeError::Random)?;
    getrandom::fill(&mut wrap_nonce).map_err(|_| ShareEnvelopeError::Random)?;

    let wrap_key = derive_share_wrap_key(shared_secret.as_slice(), &wrap_salt, &context_bytes)?;
    shared_secret.zeroize();

    let cipher = Aes256Gcm::new_from_slice(&wrap_key[..])
        .map_err(|_| ShareEnvelopeError::InvalidWrappingKey)?;
    let nonce = Nonce::<Aes256Gcm>::try_from(&wrap_nonce[..])
        .map_err(|_| ShareEnvelopeError::WrappingFailed)?;
    let aad = wrapping_aad(&context_bytes, &wrap_salt, &kem_ciphertext);

    let wrapped_file_master_key = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: file_master_key,
                aad: &aad,
            },
        )
        .map_err(|_| ShareEnvelopeError::WrappingFailed)?;

    if wrapped_file_master_key.len() != WRAPPED_FILE_MASTER_KEY_LENGTH {
        return Err(ShareEnvelopeError::InvalidWrappedKey);
    }

    Ok(RecipientShareEnvelope {
        wrap_salt,
        wrap_nonce,
        kem_ciphertext,
        wrapped_file_master_key,
    })
}

pub fn unwrap_for_recipient(
    recipient_private_key: &DecapsulationKey1024,
    context: &ShareEnvelopeContext,
    envelope: &RecipientShareEnvelope,
) -> Result<Zeroizing<[u8; FILE_MASTER_KEY_LENGTH]>, ShareEnvelopeError> {
    let context_bytes = context.encode()?;
    let public_key_bytes = recipient_private_key.encapsulation_key().to_bytes();
    let actual_key_id = key_id::from_public_key(public_key_bytes.as_slice());

    if actual_key_id != context.recipient_encryption_key_id {
        return Err(ShareEnvelopeError::RecipientKeyMismatch);
    }

    if envelope.kem_ciphertext.len() != ML_KEM_1024_CIPHERTEXT_LENGTH {
        return Err(ShareEnvelopeError::InvalidKemCiphertext);
    }

    if envelope.wrapped_file_master_key.len() != WRAPPED_FILE_MASTER_KEY_LENGTH {
        return Err(ShareEnvelopeError::InvalidWrappedKey);
    }

    let mut shared_secret = recipient_private_key
        .decapsulate_slice(&envelope.kem_ciphertext)
        .map_err(|_| ShareEnvelopeError::InvalidKemCiphertext)?;
    let wrap_key = derive_share_wrap_key(
        shared_secret.as_slice(),
        &envelope.wrap_salt,
        &context_bytes,
    )?;
    shared_secret.zeroize();

    let cipher = Aes256Gcm::new_from_slice(&wrap_key[..])
        .map_err(|_| ShareEnvelopeError::InvalidWrappingKey)?;
    let nonce = Nonce::<Aes256Gcm>::try_from(&envelope.wrap_nonce[..])
        .map_err(|_| ShareEnvelopeError::UnwrappingFailed)?;
    let aad = wrapping_aad(
        &context_bytes,
        &envelope.wrap_salt,
        &envelope.kem_ciphertext,
    );
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: &envelope.wrapped_file_master_key,
                    aad: &aad,
                },
            )
            .map_err(|_| ShareEnvelopeError::UnwrappingFailed)?,
    );

    if plaintext.len() != FILE_MASTER_KEY_LENGTH {
        return Err(ShareEnvelopeError::InvalidWrappedKey);
    }

    let mut file_master_key = Zeroizing::new([0u8; FILE_MASTER_KEY_LENGTH]);
    file_master_key.copy_from_slice(&plaintext);
    Ok(file_master_key)
}

fn derive_share_wrap_key(
    shared_secret: &[u8],
    wrap_salt: &[u8; SHARE_WRAP_SALT_LENGTH],
    context: &[u8; SHARE_CONTEXT_LENGTH],
) -> Result<Zeroizing<[u8; 32]>, ShareEnvelopeError> {
    if shared_secret.is_empty() {
        return Err(ShareEnvelopeError::Kdf);
    }

    let hkdf = Hkdf::<Sha3_512>::new(Some(wrap_salt), shared_secret);
    let mut info = Zeroizing::new(Vec::with_capacity(WRAP_KEY_DOMAIN.len() + context.len()));
    info.extend_from_slice(WRAP_KEY_DOMAIN);
    info.extend_from_slice(context);

    let mut output = Zeroizing::new([0u8; 32]);
    hkdf.expand(&info, &mut output[..])
        .map_err(|_| ShareEnvelopeError::Kdf)?;
    Ok(output)
}

fn wrapping_aad(
    context: &[u8; SHARE_CONTEXT_LENGTH],
    wrap_salt: &[u8; SHARE_WRAP_SALT_LENGTH],
    kem_ciphertext: &[u8],
) -> Zeroizing<Vec<u8>> {
    let ciphertext_hash = Sha3_512::digest(kem_ciphertext);
    let mut aad = Zeroizing::new(Vec::with_capacity(
        WRAP_AAD_DOMAIN.len() + context.len() + wrap_salt.len() + ciphertext_hash.len(),
    ));
    aad.extend_from_slice(WRAP_AAD_DOMAIN);
    aad.extend_from_slice(context);
    aad.extend_from_slice(wrap_salt);
    aad.extend_from_slice(&ciphertext_hash);
    aad
}

fn append<const N: usize>(output: &mut [u8; N], offset: &mut usize, value: &[u8]) {
    let end = *offset + value.len();
    output[*offset..end].copy_from_slice(value);
    *offset = end;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::{MlKem1024, kem::Kem};

    fn context(recipient_key_id: [u8; 32]) -> ShareEnvelopeContext {
        ShareEnvelopeContext {
            share_id: [1; 16],
            client_file_id: [2; 16],
            revision: 7,
            container_hash: [3; 64],
            owner_account_id: [4; 16],
            recipient_account_id: [5; 16],
            recipient_encryption_key_id: recipient_key_id,
            permission: PERMISSION_READ,
            expires_at_unix_seconds: 0,
        }
    }

    #[test]
    fn canonical_context_has_exact_layout() {
        let context = context([6; 32]);
        let encoded = context.encode().unwrap();

        assert_eq!(encoded.len(), SHARE_CONTEXT_LENGTH);
        assert_eq!(&encoded[0..2], &1u16.to_le_bytes());
        assert_eq!(&encoded[2..4], &SUITE_ID.to_le_bytes());
        assert_eq!(&encoded[4..20], &[1; 16]);
        assert_eq!(&encoded[20..36], &[2; 16]);
        assert_eq!(&encoded[36..44], &7u64.to_le_bytes());
        assert_eq!(&encoded[44..108], &[3; 64]);
        assert_eq!(&encoded[108..124], &[4; 16]);
        assert_eq!(&encoded[124..140], &[5; 16]);
        assert_eq!(&encoded[140..172], &[6; 32]);
        assert_eq!(&encoded[172..174], &PERMISSION_READ.to_le_bytes());
        assert_eq!(&encoded[174..182], &0u64.to_le_bytes());
    }

    #[test]
    fn wraps_existing_master_key_for_recipient() {
        let (private_key, public_key) = MlKem1024::generate_keypair();
        let key_id = key_id::from_public_key(public_key.to_bytes().as_slice());
        let context = context(key_id);
        let file_master_key = [0xA5; FILE_MASTER_KEY_LENGTH];

        let envelope = wrap_for_recipient(&public_key, &file_master_key, &context).unwrap();
        let recovered = unwrap_for_recipient(&private_key, &context, &envelope).unwrap();

        assert_eq!(&recovered[..], &file_master_key);
        assert_eq!(envelope.kem_ciphertext.len(), ML_KEM_1024_CIPHERTEXT_LENGTH);
        assert_eq!(
            envelope.wrapped_file_master_key.len(),
            WRAPPED_FILE_MASTER_KEY_LENGTH
        );
    }

    #[test]
    fn wrong_recipient_and_context_tampering_are_rejected() {
        let (private_key, public_key) = MlKem1024::generate_keypair();
        let (wrong_private_key, _) = MlKem1024::generate_keypair();
        let key_id = key_id::from_public_key(public_key.to_bytes().as_slice());
        let context = context(key_id);
        let envelope =
            wrap_for_recipient(&public_key, &[9; FILE_MASTER_KEY_LENGTH], &context).unwrap();

        assert_eq!(
            unwrap_for_recipient(&wrong_private_key, &context, &envelope),
            Err(ShareEnvelopeError::RecipientKeyMismatch)
        );

        let mut tampered = context.clone();
        tampered.container_hash[0] ^= 1;
        assert_eq!(
            unwrap_for_recipient(&private_key, &tampered, &envelope),
            Err(ShareEnvelopeError::UnwrappingFailed)
        );

        let mut tampered = context.clone();
        tampered.recipient_account_id[0] ^= 1;
        assert_eq!(
            unwrap_for_recipient(&private_key, &tampered, &envelope),
            Err(ShareEnvelopeError::UnwrappingFailed)
        );
    }

    #[test]
    fn modified_envelope_is_rejected() {
        let (private_key, public_key) = MlKem1024::generate_keypair();
        let key_id = key_id::from_public_key(public_key.to_bytes().as_slice());
        let context = context(key_id);
        let envelope =
            wrap_for_recipient(&public_key, &[8; FILE_MASTER_KEY_LENGTH], &context).unwrap();

        let mut modified = envelope.clone();
        modified.wrapped_file_master_key[0] ^= 1;
        assert_eq!(
            unwrap_for_recipient(&private_key, &context, &modified),
            Err(ShareEnvelopeError::UnwrappingFailed)
        );

        let mut modified = envelope.clone();
        modified.wrap_nonce[0] ^= 1;
        assert_eq!(
            unwrap_for_recipient(&private_key, &context, &modified),
            Err(ShareEnvelopeError::UnwrappingFailed)
        );

        let mut modified = envelope;
        modified.wrap_salt[0] ^= 1;
        assert_eq!(
            unwrap_for_recipient(&private_key, &context, &modified),
            Err(ShareEnvelopeError::UnwrappingFailed)
        );
    }

    #[test]
    fn accepts_same_account_for_device_targeted_self_share() {
        let mut self_share = context([6; 32]);
        self_share.recipient_account_id = self_share.owner_account_id;
        assert!(self_share.encode().is_ok());
    }

    #[test]
    fn rejects_invalid_context_and_key_binding() {
        let (_, public_key) = MlKem1024::generate_keypair();
        let mut invalid = context([6; 32]);
        invalid.recipient_account_id = [0; 16];
        assert_eq!(invalid.encode(), Err(ShareEnvelopeError::InvalidContext));

        let mismatched = context([7; 32]);
        assert_eq!(
            wrap_for_recipient(&public_key, &[1; FILE_MASTER_KEY_LENGTH], &mismatched,),
            Err(ShareEnvelopeError::RecipientKeyMismatch)
        );
    }

    #[test]
    fn package_has_exact_framing_and_length() {
        let (_, public_key) = MlKem1024::generate_keypair();
        let key_id = key_id::from_public_key(public_key.to_bytes().as_slice());
        let context = context(key_id);
        let envelope =
            wrap_for_recipient(&public_key, &[7; FILE_MASTER_KEY_LENGTH], &context).unwrap();

        let encoded = encode_package(&context, &envelope).unwrap();
        assert_eq!(encoded.len(), SHARE_ENVELOPE_PACKAGE_LENGTH);
        assert_eq!(&encoded[..8], SHARE_ENVELOPE_MAGIC);

        let lengths = 8 + SHARE_CONTEXT_LENGTH + SHARE_WRAP_SALT_LENGTH + SHARE_WRAP_NONCE_LENGTH;
        assert_eq!(
            &encoded[lengths..lengths + 4],
            &(ML_KEM_1024_CIPHERTEXT_LENGTH as u32).to_le_bytes()
        );
        assert_eq!(
            &encoded[lengths + 4..lengths + 8],
            &(WRAPPED_FILE_MASTER_KEY_LENGTH as u32).to_le_bytes()
        );

        let (decoded_context, decoded_envelope) = decode_package(&encoded).unwrap();
        assert_eq!(decoded_context, context);
        assert_eq!(decoded_envelope, envelope);
    }
}
