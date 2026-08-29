use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Nonce, Payload},
};
use ml_kem::{
    DecapsulationKey1024, EncapsulationKey1024,
    kem::{Decapsulate, Encapsulate, KeyExport},
};
use sha3::{Digest, Sha3_512};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    csemlk03::{
        ML_KEM_1024_CIPHERTEXT_LENGTH, OwnerKeyEnvelopeData, SUITE_ID,
        WRAPPED_FILE_MASTER_KEY_LENGTH,
    },
    kdf::{self, FILE_MASTER_KEY_LENGTH},
    key_id,
};

const WRAP_AAD_DOMAIN: &[u8] = b"FD-CSE-V3-OWNER-ENVELOPE\0";
const WRAP_SALT_LENGTH: usize = 32;
const WRAP_NONCE_LENGTH: usize = 12;

#[derive(Debug, Error)]
pub enum OwnerEnvelopeError {
    #[error("secure random generation failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error("owner-envelope KDF failed: {0}")]
    Kdf(#[from] kdf::KdfError),
    #[error("could not initialize AES-256-GCM")]
    InvalidWrappingKey,
    #[error("ML-KEM ciphertext has an invalid length")]
    InvalidKemCiphertext,
    #[error("wrapped file master key has an invalid length")]
    InvalidWrappedKey,
    #[error("owner envelope belongs to another encryption key")]
    RecipientKeyMismatch,
    #[error("unsupported cryptographic suite")]
    UnsupportedSuite,
    #[error("file master key wrapping failed")]
    WrappingFailed,
    #[error("file master key authentication or unwrapping failed")]
    UnwrappingFailed,
}

/// The public envelope plus the secret needed for subsequent content and
/// metadata encryption. This type deliberately does not implement `Debug`.
pub struct WrappedOwnerEnvelope {
    envelope: OwnerKeyEnvelopeData,
    file_master_key: Zeroizing<[u8; FILE_MASTER_KEY_LENGTH]>,
}

impl WrappedOwnerEnvelope {
    pub fn envelope(&self) -> &OwnerKeyEnvelopeData {
        &self.envelope
    }

    pub fn file_master_key(&self) -> &[u8; FILE_MASTER_KEY_LENGTH] {
        &self.file_master_key
    }

    pub fn into_parts(
        self,
    ) -> (
        OwnerKeyEnvelopeData,
        Zeroizing<[u8; FILE_MASTER_KEY_LENGTH]>,
    ) {
        (self.envelope, self.file_master_key)
    }
}

/// Creates the immutable owner envelope using only the recipient's public key.
pub fn wrap_for_owner(
    public_key: &EncapsulationKey1024,
    client_file_id: &[u8; 16],
) -> Result<WrappedOwnerEnvelope, OwnerEnvelopeError> {
    let public_key_bytes = public_key.to_bytes();
    let recipient_key_id = key_id::from_public_key(public_key_bytes.as_slice());

    let (kem_ciphertext, mut shared_secret) = public_key.encapsulate();
    let kem_ciphertext = kem_ciphertext.as_slice().to_vec();

    let mut file_master_key = Zeroizing::new([0u8; FILE_MASTER_KEY_LENGTH]);
    let mut wrap_salt = [0u8; WRAP_SALT_LENGTH];
    let mut wrap_nonce = [0u8; WRAP_NONCE_LENGTH];
    getrandom::fill(&mut file_master_key[..])?;
    getrandom::fill(&mut wrap_salt)?;
    getrandom::fill(&mut wrap_nonce)?;

    let wrap_key = kdf::derive_wrap_key(
        shared_secret.as_slice(),
        &wrap_salt,
        client_file_id,
        &recipient_key_id,
    )?;
    shared_secret.zeroize();

    let cipher = Aes256Gcm::new_from_slice(&wrap_key[..])
        .map_err(|_| OwnerEnvelopeError::InvalidWrappingKey)?;
    let nonce = Nonce::<Aes256Gcm>::try_from(&wrap_nonce[..])
        .map_err(|_| OwnerEnvelopeError::WrappingFailed)?;
    let aad = wrapping_aad(
        client_file_id,
        SUITE_ID,
        &recipient_key_id,
        &kem_ciphertext,
    );
    let wrapped_file_master_key = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &file_master_key[..],
                aad: &aad,
            },
        )
        .map_err(|_| OwnerEnvelopeError::WrappingFailed)?;

    Ok(WrappedOwnerEnvelope {
        envelope: OwnerKeyEnvelopeData {
            recipient_encryption_key_id: recipient_key_id,
            wrap_salt,
            wrap_nonce,
            kem_ciphertext,
            wrapped_file_master_key,
        },
        file_master_key,
    })
}

/// Authenticates and unwraps an owner envelope using the selected private key.
pub fn unwrap_for_owner(
    private_key: &DecapsulationKey1024,
    client_file_id: &[u8; 16],
    suite_id: u16,
    envelope: &OwnerKeyEnvelopeData,
) -> Result<Zeroizing<[u8; FILE_MASTER_KEY_LENGTH]>, OwnerEnvelopeError> {
    if suite_id != SUITE_ID {
        return Err(OwnerEnvelopeError::UnsupportedSuite);
    }
    if envelope.kem_ciphertext.len() != ML_KEM_1024_CIPHERTEXT_LENGTH {
        return Err(OwnerEnvelopeError::InvalidKemCiphertext);
    }
    if envelope.wrapped_file_master_key.len() != WRAPPED_FILE_MASTER_KEY_LENGTH {
        return Err(OwnerEnvelopeError::InvalidWrappedKey);
    }

    let public_key_bytes = private_key.encapsulation_key().to_bytes();
    let actual_key_id = key_id::from_public_key(public_key_bytes.as_slice());
    if actual_key_id != envelope.recipient_encryption_key_id {
        return Err(OwnerEnvelopeError::RecipientKeyMismatch);
    }

    let mut shared_secret = private_key
        .decapsulate_slice(&envelope.kem_ciphertext)
        .map_err(|_| OwnerEnvelopeError::InvalidKemCiphertext)?;
    let wrap_key = kdf::derive_wrap_key(
        shared_secret.as_slice(),
        &envelope.wrap_salt,
        client_file_id,
        &envelope.recipient_encryption_key_id,
    )?;
    shared_secret.zeroize();

    let cipher = Aes256Gcm::new_from_slice(&wrap_key[..])
        .map_err(|_| OwnerEnvelopeError::InvalidWrappingKey)?;
    let nonce = Nonce::<Aes256Gcm>::try_from(&envelope.wrap_nonce[..])
        .map_err(|_| OwnerEnvelopeError::UnwrappingFailed)?;
    let aad = wrapping_aad(
        client_file_id,
        suite_id,
        &envelope.recipient_encryption_key_id,
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
            .map_err(|_| OwnerEnvelopeError::UnwrappingFailed)?,
    );
    if plaintext.len() != FILE_MASTER_KEY_LENGTH {
        return Err(OwnerEnvelopeError::InvalidWrappedKey);
    }

    let mut file_master_key = Zeroizing::new([0u8; FILE_MASTER_KEY_LENGTH]);
    file_master_key.copy_from_slice(&plaintext);
    Ok(file_master_key)
}

fn wrapping_aad(
    client_file_id: &[u8; 16],
    suite_id: u16,
    recipient_key_id: &[u8; 32],
    kem_ciphertext: &[u8],
) -> Zeroizing<Vec<u8>> {
    let ciphertext_hash = Sha3_512::digest(kem_ciphertext);
    let mut aad = Zeroizing::new(Vec::with_capacity(
        WRAP_AAD_DOMAIN.len() + 16 + 2 + 32 + 64,
    ));
    aad.extend_from_slice(WRAP_AAD_DOMAIN);
    aad.extend_from_slice(client_file_id);
    aad.extend_from_slice(&suite_id.to_le_bytes());
    aad.extend_from_slice(recipient_key_id);
    aad.extend_from_slice(&ciphertext_hash);
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::{MlKem1024, kem::Kem};

    const FILE_ID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];

    #[test]
    fn owner_envelope_wraps_and_unwraps_file_master_key() {
        let (private_key, public_key) = MlKem1024::generate_keypair();
        let wrapped = wrap_for_owner(&public_key, &FILE_ID).unwrap();
        assert_eq!(wrapped.envelope().kem_ciphertext.len(), ML_KEM_1024_CIPHERTEXT_LENGTH);
        assert_eq!(wrapped.envelope().wrapped_file_master_key.len(), WRAPPED_FILE_MASTER_KEY_LENGTH);
        assert_eq!(
            wrapped.envelope().recipient_encryption_key_id,
            key_id::from_public_key(public_key.to_bytes().as_slice())
        );
        let recovered = unwrap_for_owner(&private_key, &FILE_ID, SUITE_ID, wrapped.envelope()).unwrap();
        assert_eq!(&recovered[..], &wrapped.file_master_key()[..]);
    }

    #[test]
    fn wrong_private_key_is_rejected() {
        let (_, public_key) = MlKem1024::generate_keypair();
        let (wrong_private_key, _) = MlKem1024::generate_keypair();
        let wrapped = wrap_for_owner(&public_key, &FILE_ID).unwrap();
        assert!(matches!(
            unwrap_for_owner(&wrong_private_key, &FILE_ID, SUITE_ID, wrapped.envelope()),
            Err(OwnerEnvelopeError::RecipientKeyMismatch)
        ));
    }

    #[test]
    fn tampering_is_rejected() {
        let (private_key, public_key) = MlKem1024::generate_keypair();
        let wrapped = wrap_for_owner(&public_key, &FILE_ID).unwrap();

        let mut kem = wrapped.envelope().clone(); kem.kem_ciphertext[0] ^= 1;
        assert!(matches!(unwrap_for_owner(&private_key, &FILE_ID, SUITE_ID, &kem), Err(OwnerEnvelopeError::UnwrappingFailed)));

        let mut ciphertext = wrapped.envelope().clone(); ciphertext.wrapped_file_master_key[0] ^= 1;
        assert!(matches!(unwrap_for_owner(&private_key, &FILE_ID, SUITE_ID, &ciphertext), Err(OwnerEnvelopeError::UnwrappingFailed)));

        let mut nonce = wrapped.envelope().clone(); nonce.wrap_nonce[0] ^= 1;
        assert!(matches!(unwrap_for_owner(&private_key, &FILE_ID, SUITE_ID, &nonce), Err(OwnerEnvelopeError::UnwrappingFailed)));

        let mut salt = wrapped.envelope().clone(); salt.wrap_salt[0] ^= 1;
        assert!(matches!(unwrap_for_owner(&private_key, &FILE_ID, SUITE_ID, &salt), Err(OwnerEnvelopeError::UnwrappingFailed)));

        let mut key_id = wrapped.envelope().clone(); key_id.recipient_encryption_key_id[0] ^= 1;
        assert!(matches!(unwrap_for_owner(&private_key, &FILE_ID, SUITE_ID, &key_id), Err(OwnerEnvelopeError::RecipientKeyMismatch)));

        let mut wrong_file_id = FILE_ID; wrong_file_id[0] ^= 1;
        assert!(matches!(unwrap_for_owner(&private_key, &wrong_file_id, SUITE_ID, wrapped.envelope()), Err(OwnerEnvelopeError::UnwrappingFailed)));
        assert!(matches!(unwrap_for_owner(&private_key, &FILE_ID, 2, wrapped.envelope()), Err(OwnerEnvelopeError::UnsupportedSuite)));
    }

    #[test]
    fn separate_wraps_use_fresh_randomness_and_master_keys() {
        let (_, public_key) = MlKem1024::generate_keypair();
        let first = wrap_for_owner(&public_key, &FILE_ID).unwrap();
        let second = wrap_for_owner(&public_key, &FILE_ID).unwrap();
        assert_ne!(first.file_master_key(), second.file_master_key());
        assert_ne!(first.envelope().wrap_salt, second.envelope().wrap_salt);
        assert_ne!(first.envelope().wrap_nonce, second.envelope().wrap_nonce);
        assert_ne!(first.envelope().kem_ciphertext, second.envelope().kem_ciphertext);
        assert_ne!(first.envelope().wrapped_file_master_key, second.envelope().wrapped_file_master_key);
    }
}
