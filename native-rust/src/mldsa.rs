use ml_dsa::{
    EncodedVerifyingKey, Generate, Keypair, MlDsa87, Seed, Signature, Signer, SigningKey, Verifier,
    VerifyingKey,
};
use thiserror::Error;
use zeroize::Zeroizing;

pub const ML_DSA_87_PRIVATE_SEED_LENGTH: usize = 32;
pub const ML_DSA_87_PUBLIC_KEY_LENGTH: usize = 2_592;
pub const ML_DSA_87_SIGNATURE_LENGTH: usize = 4_627;

#[derive(Debug, Error)]
pub enum MlDsaError {
    #[error("ML-DSA-87 private seed has an invalid length: found {0} bytes, expected 32")]
    InvalidPrivateSeedLength(usize),

    #[error("ML-DSA-87 public key has an invalid length: found {0} bytes, expected 2592")]
    InvalidPublicKeyLength(usize),

    #[error("ML-DSA-87 signature has an invalid length: found {0} bytes, expected 4627")]
    InvalidSignatureLength(usize),

    #[error("ML-DSA-87 signature encoding is invalid")]
    InvalidSignatureEncoding,

    #[error("ML-DSA-87 signature verification failed")]
    VerificationFailed,
}

/// Newly generated ML-DSA-87 key material.
///
/// The private component is retained only as the canonical 32-byte seed so it
/// can later be protected with DPAPI. The expanded signing key is not stored.
pub struct MlDsa87Keypair {
    private_seed: Zeroizing<[u8; ML_DSA_87_PRIVATE_SEED_LENGTH]>,
    public_key: [u8; ML_DSA_87_PUBLIC_KEY_LENGTH],
}

impl MlDsa87Keypair {
    pub fn private_seed(&self) -> &[u8; ML_DSA_87_PRIVATE_SEED_LENGTH] {
        &self.private_seed
    }

    pub fn public_key(&self) -> &[u8; ML_DSA_87_PUBLIC_KEY_LENGTH] {
        &self.public_key
    }
}

/// Generates a fresh ML-DSA-87 signing key using the operating-system RNG.
pub fn generate_mldsa87_keypair() -> MlDsa87Keypair {
    let signing_key = SigningKey::<MlDsa87>::generate();
    let seed = signing_key.to_seed();
    let encoded_public_key = signing_key.verifying_key().encode();

    let mut private_seed = Zeroizing::new([0u8; ML_DSA_87_PRIVATE_SEED_LENGTH]);
    private_seed.copy_from_slice(seed.as_slice());

    let mut public_key = [0u8; ML_DSA_87_PUBLIC_KEY_LENGTH];
    public_key.copy_from_slice(encoded_public_key.as_slice());

    MlDsa87Keypair {
        private_seed,
        public_key,
    }
}

/// Signs the exact message bytes with an ML-DSA-87 private seed.
///
/// Domain separation belongs to the caller. Enrollment and manifest callers
/// must pass their complete canonical, domain-prefixed message.
pub fn sign_mldsa87(
    private_seed: &[u8],
    message: &[u8],
) -> Result<[u8; ML_DSA_87_SIGNATURE_LENGTH], MlDsaError> {
    let seed = Seed::try_from(private_seed)
        .map_err(|_| MlDsaError::InvalidPrivateSeedLength(private_seed.len()))?;

    let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);
    let signature = signing_key.sign(message);
    let encoded_signature = signature.encode();

    let mut signature_bytes = [0u8; ML_DSA_87_SIGNATURE_LENGTH];
    signature_bytes.copy_from_slice(encoded_signature.as_slice());

    Ok(signature_bytes)
}

/// Verifies an ML-DSA-87 signature over the exact message bytes.
pub fn verify_mldsa87(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), MlDsaError> {
    let encoded_public_key = EncodedVerifyingKey::<MlDsa87>::try_from(public_key)
        .map_err(|_| MlDsaError::InvalidPublicKeyLength(public_key.len()))?;

    if signature.len() != ML_DSA_87_SIGNATURE_LENGTH {
        return Err(MlDsaError::InvalidSignatureLength(signature.len()));
    }

    let signature = Signature::<MlDsa87>::try_from(signature)
        .map_err(|_| MlDsaError::InvalidSignatureEncoding)?;

    let verifying_key = VerifyingKey::<MlDsa87>::decode(&encoded_public_key);

    verifying_key
        .verify(message, &signature)
        .map_err(|_| MlDsaError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_mldsa87_key_signs_and_verifies() {
        let generated = generate_mldsa87_keypair();

        assert_eq!(
            generated.private_seed().len(),
            ML_DSA_87_PRIVATE_SEED_LENGTH,
        );
        assert_eq!(generated.public_key().len(), ML_DSA_87_PUBLIC_KEY_LENGTH,);

        let message = b"FD-LOCKBOX-ML-DSA-87-SELF-TEST\0";
        let signature = sign_mldsa87(generated.private_seed(), message)
            .expect("generated private seed should sign");

        verify_mldsa87(generated.public_key(), message, &signature)
            .expect("generated ML-DSA-87 signature should verify");

        assert!(
            verify_mldsa87(generated.public_key(), b"modified message", &signature,).is_err(),
            "the signature must not verify for another message",
        );
    }

    #[test]
    fn modified_mldsa87_signature_is_rejected() {
        let generated = generate_mldsa87_keypair();
        let message = b"canonical enrollment transcript";
        let mut signature = sign_mldsa87(generated.private_seed(), message)
            .expect("generated private seed should sign");

        signature[0] ^= 0x01;

        assert!(verify_mldsa87(generated.public_key(), message, &signature,).is_err(),);
    }

    #[test]
    fn invalid_mldsa87_lengths_are_rejected() {
        let generated = generate_mldsa87_keypair();
        let message = b"canonical enrollment transcript";
        let signature = sign_mldsa87(generated.private_seed(), message)
            .expect("generated private seed should sign");

        assert!(matches!(
            sign_mldsa87(&[0u8; 31], message),
            Err(MlDsaError::InvalidPrivateSeedLength(31)),
        ));

        assert!(matches!(
            verify_mldsa87(
                &generated.public_key()[..ML_DSA_87_PUBLIC_KEY_LENGTH - 1],
                message,
                &signature,
            ),
            Err(MlDsaError::InvalidPublicKeyLength(2_591)),
        ));

        assert!(matches!(
            verify_mldsa87(
                generated.public_key(),
                message,
                &signature[..ML_DSA_87_SIGNATURE_LENGTH - 1],
            ),
            Err(MlDsaError::InvalidSignatureLength(4_626)),
        ));
    }
}
