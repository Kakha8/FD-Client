use ml_dsa::{Generate, Keypair, MlDsa87, SigningKey};
use zeroize::Zeroizing;

pub const ML_DSA_87_PRIVATE_SEED_LENGTH: usize = 32;
pub const ML_DSA_87_PUBLIC_KEY_LENGTH: usize = 2_592;

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

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::{EncodedVerifyingKey, Seed, Signer, Verifier, VerifyingKey};

    #[test]
    fn generated_mldsa87_key_signs_and_verifies() {
        let generated = generate_mldsa87_keypair();

        assert_eq!(
            generated.private_seed().len(),
            ML_DSA_87_PRIVATE_SEED_LENGTH,
        );
        assert_eq!(generated.public_key().len(), ML_DSA_87_PUBLIC_KEY_LENGTH,);

        let seed = Seed::try_from(generated.private_seed().as_slice())
            .expect("generated seed has the required length");
        let signing_key = SigningKey::<MlDsa87>::from_seed(&seed);

        let encoded_public_key =
            EncodedVerifyingKey::<MlDsa87>::try_from(generated.public_key().as_slice())
                .expect("generated public key has the required length");
        let verifying_key = VerifyingKey::<MlDsa87>::decode(&encoded_public_key);

        let message = b"FD-LOCKBOX-ML-DSA-87-SELF-TEST\0";
        let signature = signing_key.sign(message);

        verifying_key
            .verify(message, &signature)
            .expect("generated ML-DSA-87 signature should verify");

        assert!(
            verifying_key
                .verify(b"modified message", &signature)
                .is_err(),
            "the signature must not verify for another message",
        );
    }
}
