use sha3::{Digest, Sha3_256};

pub const KEY_ID_LENGTH: usize = 32;

/// Calculates the protocol key ID from the canonical public-key bytes.
pub fn from_public_key(public_key: &[u8]) -> [u8; KEY_ID_LENGTH] {
    Sha3_256::digest(public_key).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_matches_known_sha3_256_vector() {
        let actual = from_public_key(b"FD-LOCKBOX-PUBLIC-KEY-TEST-V1\0");
        let expected = [
            0x06, 0xa5, 0xf1, 0x6f, 0x09, 0xcc, 0x83, 0x0a,
            0xbf, 0xa4, 0x32, 0x59, 0xd4, 0x29, 0x55, 0xe3,
            0x03, 0x61, 0xeb, 0x3a, 0x8f, 0x10, 0x79, 0x64,
            0x01, 0xae, 0x17, 0x20, 0x38, 0x29, 0xf8, 0x54,
        ];
        assert_eq!(actual, expected);
    }

    #[test]
    fn key_id_is_deterministic_and_sensitive_to_public_key_bytes() {
        let public_key = [0xA5; 1_568];
        assert_eq!(from_public_key(&public_key), from_public_key(&public_key));

        let mut modified = public_key;
        modified[1_567] ^= 1;
        assert_ne!(from_public_key(&public_key), from_public_key(&modified));
    }
}
