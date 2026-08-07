use hkdf::Hkdf;
use sha3::Sha3_512;
use thiserror::Error;
use zeroize::Zeroizing;

pub const FILE_MASTER_KEY_LENGTH: usize = 32;
pub const DERIVED_KEY_LENGTH: usize = 32;
pub const FILE_KDF_SALT_LENGTH: usize = 32;
pub const WRAP_SALT_LENGTH: usize = 32;
pub const KEY_ID_LENGTH: usize = 32;
pub const CLIENT_FILE_ID_LENGTH: usize = 16;

const CONTENT_KEY_LABEL: &[u8] = b"FD-CSE-V3-CONTENT-KEY\0";
const METADATA_KEY_LABEL: &[u8] = b"FD-CSE-V3-METADATA-KEY\0";
const WRAP_KEY_LABEL: &[u8] = b"FD-CSE-V3-WRAP-KEY\0";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum KdfError {
    #[error("HKDF input has an invalid length")]
    InvalidInputLength,
    #[error("HKDF output length is invalid")]
    InvalidOutputLength,
}

pub struct FileKeys {
    content_key: Zeroizing<[u8; DERIVED_KEY_LENGTH]>,
    metadata_key: Zeroizing<[u8; DERIVED_KEY_LENGTH]>,
}

impl FileKeys {
    pub fn content_key(&self) -> &[u8; DERIVED_KEY_LENGTH] {
        &self.content_key
    }

    pub fn metadata_key(&self) -> &[u8; DERIVED_KEY_LENGTH] {
        &self.metadata_key
    }
}

pub fn derive_file_keys(
    file_master_key: &[u8],
    file_kdf_salt: &[u8],
    client_file_id: &[u8; CLIENT_FILE_ID_LENGTH],
) -> Result<FileKeys, KdfError> {
    if file_master_key.len() != FILE_MASTER_KEY_LENGTH
        || file_kdf_salt.len() != FILE_KDF_SALT_LENGTH
    {
        return Err(KdfError::InvalidInputLength);
    }

    let hkdf = Hkdf::<Sha3_512>::new(Some(file_kdf_salt), file_master_key);
    let content_key = expand(&hkdf, CONTENT_KEY_LABEL, client_file_id, None)?;
    let metadata_key = expand(&hkdf, METADATA_KEY_LABEL, client_file_id, None)?;

    Ok(FileKeys {
        content_key: Zeroizing::new(content_key),
        metadata_key: Zeroizing::new(metadata_key),
    })
}

pub fn derive_wrap_key(
    ml_kem_shared_secret: &[u8],
    wrap_salt: &[u8],
    client_file_id: &[u8; CLIENT_FILE_ID_LENGTH],
    recipient_encryption_key_id: &[u8; KEY_ID_LENGTH],
) -> Result<Zeroizing<[u8; DERIVED_KEY_LENGTH]>, KdfError> {
    if ml_kem_shared_secret.is_empty() || wrap_salt.len() != WRAP_SALT_LENGTH {
        return Err(KdfError::InvalidInputLength);
    }

    let hkdf = Hkdf::<Sha3_512>::new(Some(wrap_salt), ml_kem_shared_secret);
    Ok(Zeroizing::new(expand(
        &hkdf,
        WRAP_KEY_LABEL,
        client_file_id,
        Some(recipient_encryption_key_id),
    )?))
}

fn expand(
    hkdf: &Hkdf<Sha3_512>,
    label: &[u8],
    client_file_id: &[u8; CLIENT_FILE_ID_LENGTH],
    key_id: Option<&[u8; KEY_ID_LENGTH]>,
) -> Result<[u8; DERIVED_KEY_LENGTH], KdfError> {
    let capacity = label.len() + client_file_id.len() + key_id.map_or(0, |id| id.len());
    let mut info = Zeroizing::new(Vec::with_capacity(capacity));
    info.extend_from_slice(label);
    info.extend_from_slice(client_file_id);
    if let Some(key_id) = key_id {
        info.extend_from_slice(key_id);
    }

    let mut output = [0u8; DERIVED_KEY_LENGTH];
    hkdf.expand(info.as_slice(), &mut output)
        .map_err(|_| KdfError::InvalidOutputLength)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE_MASTER_KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    const SALT: [u8; 32] = [0xA5; 32];
    const FILE_ID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];

    #[test]
    fn file_keys_match_known_hkdf_sha3_512_vectors() {
        let keys = derive_file_keys(&FILE_MASTER_KEY, &SALT, &FILE_ID).unwrap();
        assert_eq!(keys.content_key(), &[
            0x55, 0x4f, 0x91, 0xee, 0x60, 0xb5, 0xeb, 0x50,
            0x22, 0x93, 0xac, 0x6c, 0x0e, 0x56, 0x4f, 0x63,
            0xf6, 0x5a, 0xf7, 0x2b, 0x41, 0x6e, 0x57, 0x3f,
            0x56, 0x64, 0x50, 0x80, 0xbb, 0x04, 0xeb, 0xff,
        ]);
        assert_eq!(keys.metadata_key(), &[
            0x5d, 0x6e, 0xab, 0xe7, 0xe7, 0x4d, 0x0c, 0xd8,
            0x98, 0x42, 0x0e, 0xb1, 0xaa, 0xe0, 0xd1, 0xbf,
            0xfb, 0xa5, 0x45, 0xd3, 0x7c, 0xe9, 0xdc, 0x54,
            0x31, 0x42, 0x47, 0x6b, 0x0c, 0xb9, 0xda, 0x7d,
        ]);
    }

    #[test]
    fn wrap_key_matches_known_hkdf_sha3_512_vector() {
        let shared_secret = [0x3C; 32];
        let key_id = [0x5A; 32];
        let key = derive_wrap_key(&shared_secret, &SALT, &FILE_ID, &key_id).unwrap();
        assert_eq!(&*key, &[
            0xe5, 0xb8, 0xde, 0x4f, 0xf7, 0xa6, 0x7b, 0x0a,
            0x60, 0x1c, 0xcc, 0x18, 0x10, 0xef, 0x08, 0x32,
            0x8a, 0x12, 0x5c, 0x89, 0x77, 0x87, 0xef, 0x52,
            0x34, 0x8c, 0x07, 0x81, 0x06, 0xff, 0x85, 0x5e,
        ]);
    }

    #[test]
    fn domains_and_context_values_produce_distinct_keys() {
        let keys = derive_file_keys(&FILE_MASTER_KEY, &SALT, &FILE_ID).unwrap();
        assert_ne!(keys.content_key(), keys.metadata_key());

        let mut other_id = FILE_ID;
        other_id[15] ^= 1;
        let other = derive_file_keys(&FILE_MASTER_KEY, &SALT, &other_id).unwrap();
        assert_ne!(keys.content_key(), other.content_key());
    }

    #[test]
    fn invalid_input_lengths_are_rejected() {
        assert!(matches!(
            derive_file_keys(&FILE_MASTER_KEY[..31], &SALT, &FILE_ID),
            Err(KdfError::InvalidInputLength)
        ));
        assert_eq!(
            derive_wrap_key(&[], &SALT, &FILE_ID, &[0; 32]).unwrap_err(),
            KdfError::InvalidInputLength
        );
    }
}
