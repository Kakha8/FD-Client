use std::io::{Read, Write};

use aes_gcm::{
    Aes256Gcm,
    aead::{Aead, KeyInit, Nonce, Payload},
};
use sha3::{Digest, Sha3_512};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{
    csemlk03::CHUNK_SIZE,
    kdf::{self, FILE_MASTER_KEY_LENGTH},
};

const CONTENT_AAD_DOMAIN: &[u8] = b"FD-CSE-V3-CONTENT-CHUNK\0";
const GCM_TAG_LENGTH: usize = 16;
pub const STORED_CHUNK_LENGTH: usize = CHUNK_SIZE as usize + GCM_TAG_LENGTH;

#[derive(Debug, Error)]
pub enum ContentCryptoError {
    #[error("content KDF failed: {0}")]
    Kdf(#[from] kdf::KdfError),
    #[error("secure random generation failed: {0}")]
    Random(#[from] getrandom::Error),
    #[error("content I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("plaintext size requires too many chunks")]
    TooManyChunks,
    #[error("chunk count does not match the exact plaintext size")]
    ChunkCountMismatch,
    #[error("plaintext is shorter than its declared exact size")]
    TruncatedPlaintext,
    #[error("plaintext contains data after its declared exact size")]
    TrailingPlaintext,
    #[error("encrypted content is truncated")]
    TruncatedCiphertext,
    #[error("encrypted content contains trailing data")]
    TrailingCiphertext,
    #[error("could not initialize content AES-256-GCM")]
    InvalidContentKey,
    #[error("content chunk encryption failed")]
    EncryptionFailed,
    #[error("content chunk {0} failed authentication")]
    AuthenticationFailed(u32),
}

pub fn chunk_count(exact_plaintext_size: u64) -> Result<u32, ContentCryptoError> {
    let chunk_size = u64::from(CHUNK_SIZE);
    let count = if exact_plaintext_size == 0 {
        1
    } else {
        exact_plaintext_size / chunk_size
            + u64::from(exact_plaintext_size % chunk_size != 0)
    };
    u32::try_from(count).map_err(|_| ContentCryptoError::TooManyChunks)
}

pub struct ContentContext<'a> {
    pub file_master_key: &'a [u8; FILE_MASTER_KEY_LENGTH],
    pub file_kdf_salt: &'a [u8; 32],
    pub client_file_id: &'a [u8; 16],
    pub content_nonce_prefix: &'a [u8; 8],
    pub exact_header_bytes: &'a [u8],
}

pub fn encrypt_content<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    exact_plaintext_size: u64,
    context: &ContentContext<'_>,
) -> Result<u32, ContentCryptoError> {
    let count = chunk_count(exact_plaintext_size)?;
    let keys = kdf::derive_file_keys(
        context.file_master_key,
        context.file_kdf_salt,
        context.client_file_id,
    )?;
    let cipher = Aes256Gcm::new_from_slice(keys.content_key())
        .map_err(|_| ContentCryptoError::InvalidContentKey)?;
    let header_hash: [u8; 64] = Sha3_512::digest(context.exact_header_bytes).into();
    let mut remaining = exact_plaintext_size;

    for index in 0..count {
        let plaintext_length = remaining.min(u64::from(CHUNK_SIZE)) as usize;
        let mut padded = Zeroizing::new(vec![0u8; CHUNK_SIZE as usize]);
        read_exact_plaintext(input, &mut padded[..plaintext_length])?;
        if plaintext_length < padded.len() {
            getrandom::fill(&mut padded[plaintext_length..])?;
        }

        let nonce_bytes = content_nonce(context.content_nonce_prefix, index);
        let nonce = Nonce::<Aes256Gcm>::try_from(&nonce_bytes[..])
            .map_err(|_| ContentCryptoError::EncryptionFailed)?;
        let aad = chunk_aad(&header_hash, context.client_file_id, index);
        let encrypted = cipher.encrypt(
            &nonce,
            Payload { msg: &padded, aad: &aad },
        ).map_err(|_| ContentCryptoError::EncryptionFailed)?;
        if encrypted.len() != STORED_CHUNK_LENGTH {
            return Err(ContentCryptoError::EncryptionFailed);
        }
        output.write_all(&encrypted)?;
        remaining -= plaintext_length as u64;
    }

    if remaining != 0 {
        return Err(ContentCryptoError::ChunkCountMismatch);
    }
    let mut probe = [0u8; 1];
    if input.read(&mut probe)? != 0 {
        return Err(ContentCryptoError::TrailingPlaintext);
    }
    Ok(count)
}

pub fn decrypt_content<R: Read, W: Write>(
    input: &mut R,
    output: &mut W,
    exact_plaintext_size: u64,
    declared_chunk_count: u32,
    context: &ContentContext<'_>,
) -> Result<(), ContentCryptoError> {
    let expected_count = chunk_count(exact_plaintext_size)?;
    if declared_chunk_count != expected_count {
        return Err(ContentCryptoError::ChunkCountMismatch);
    }
    let keys = kdf::derive_file_keys(
        context.file_master_key,
        context.file_kdf_salt,
        context.client_file_id,
    )?;
    let cipher = Aes256Gcm::new_from_slice(keys.content_key())
        .map_err(|_| ContentCryptoError::InvalidContentKey)?;
    let header_hash: [u8; 64] = Sha3_512::digest(context.exact_header_bytes).into();
    let mut remaining = exact_plaintext_size;

    for index in 0..declared_chunk_count {
        let mut encrypted = vec![0u8; STORED_CHUNK_LENGTH];
        read_exact_ciphertext(input, &mut encrypted)?;
        let nonce_bytes = content_nonce(context.content_nonce_prefix, index);
        let nonce = Nonce::<Aes256Gcm>::try_from(&nonce_bytes[..])
            .map_err(|_| ContentCryptoError::AuthenticationFailed(index))?;
        let aad = chunk_aad(&header_hash, context.client_file_id, index);
        let plaintext = Zeroizing::new(cipher.decrypt(
            &nonce,
            Payload { msg: &encrypted, aad: &aad },
        ).map_err(|_| ContentCryptoError::AuthenticationFailed(index))?);
        if plaintext.len() != CHUNK_SIZE as usize {
            return Err(ContentCryptoError::AuthenticationFailed(index));
        }
        let write_length = remaining.min(u64::from(CHUNK_SIZE)) as usize;
        output.write_all(&plaintext[..write_length])?;
        remaining -= write_length as u64;
    }

    if remaining != 0 {
        return Err(ContentCryptoError::ChunkCountMismatch);
    }
    let mut probe = [0u8; 1];
    if input.read(&mut probe)? != 0 {
        return Err(ContentCryptoError::TrailingCiphertext);
    }
    Ok(())
}

fn content_nonce(prefix: &[u8; 8], chunk_index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(prefix);
    nonce[8..].copy_from_slice(&chunk_index.to_le_bytes());
    nonce
}

fn chunk_aad(
    header_hash: &[u8; 64],
    client_file_id: &[u8; 16],
    chunk_index: u32,
) -> Zeroizing<Vec<u8>> {
    let mut aad = Zeroizing::new(Vec::with_capacity(
        CONTENT_AAD_DOMAIN.len() + 64 + 16 + 4 + 4,
    ));
    aad.extend_from_slice(CONTENT_AAD_DOMAIN);
    aad.extend_from_slice(header_hash);
    aad.extend_from_slice(client_file_id);
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad.extend_from_slice(&CHUNK_SIZE.to_le_bytes());
    aad
}

fn read_exact_plaintext<R: Read>(
    input: &mut R,
    buffer: &mut [u8],
) -> Result<(), ContentCryptoError> {
    input.read_exact(buffer).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            ContentCryptoError::TruncatedPlaintext
        } else {
            ContentCryptoError::Io(error)
        }
    })
}

fn read_exact_ciphertext<R: Read>(
    input: &mut R,
    buffer: &mut [u8],
) -> Result<(), ContentCryptoError> {
    input.read_exact(buffer).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            ContentCryptoError::TruncatedCiphertext
        } else {
            ContentCryptoError::Io(error)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const MASTER_KEY: [u8; 32] = [0x11; 32];
    const KDF_SALT: [u8; 32] = [0x22; 32];
    const FILE_ID: [u8; 16] = [0x33; 16];
    const NONCE_PREFIX: [u8; 8] = [0x44; 8];
    const HEADER: [u8; 96] = [0x55; 96];

    fn context<'a>(
        master_key: &'a [u8; 32],
        file_id: &'a [u8; 16],
        header: &'a [u8],
    ) -> ContentContext<'a> {
        ContentContext {
            file_master_key: master_key,
            file_kdf_salt: &KDF_SALT,
            client_file_id: file_id,
            content_nonce_prefix: &NONCE_PREFIX,
            exact_header_bytes: header,
        }
    }

    fn round_trip(size: usize) {
        let plaintext: Vec<u8> = (0..size).map(|index| (index % 251) as u8).collect();
        let mut encrypted = Vec::new();
        let count = encrypt_content(
            &mut Cursor::new(&plaintext),
            &mut encrypted,
            size as u64,
            &context(&MASTER_KEY, &FILE_ID, &HEADER),
        ).unwrap();
        assert_eq!(count, chunk_count(size as u64).unwrap());
        assert_eq!(encrypted.len(), count as usize * STORED_CHUNK_LENGTH);

        let mut recovered = Vec::new();
        decrypt_content(
            &mut Cursor::new(&encrypted),
            &mut recovered,
            size as u64,
            count,
            &context(&MASTER_KEY, &FILE_ID, &HEADER),
        ).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn boundary_sizes_round_trip_with_fixed_stored_chunks() {
        for size in [
            0,
            1,
            CHUNK_SIZE as usize - 1,
            CHUNK_SIZE as usize,
            CHUNK_SIZE as usize + 1,
            CHUNK_SIZE as usize * 2 + 17,
        ] {
            round_trip(size);
        }
    }

    #[test]
    fn ciphertext_tag_wrong_key_header_uuid_and_index_are_rejected() {
        let plaintext = vec![0xAB; CHUNK_SIZE as usize + 1];
        let mut encrypted = Vec::new();
        let count = encrypt_content(
            &mut Cursor::new(&plaintext), &mut encrypted, plaintext.len() as u64,
            &context(&MASTER_KEY, &FILE_ID, &HEADER),
        ).unwrap();

        for offset in [0, CHUNK_SIZE as usize] {
            let mut modified = encrypted.clone(); modified[offset] ^= 1;
            assert!(matches!(decrypt_content(
                &mut Cursor::new(modified), &mut Vec::new(), plaintext.len() as u64,
                count, &context(&MASTER_KEY, &FILE_ID, &HEADER),
            ), Err(ContentCryptoError::AuthenticationFailed(0))));
        }

        let wrong_key = [0x12; 32];
        assert!(matches!(decrypt_content(
            &mut Cursor::new(&encrypted), &mut Vec::new(), plaintext.len() as u64,
            count, &context(&wrong_key, &FILE_ID, &HEADER),
        ), Err(ContentCryptoError::AuthenticationFailed(0))));

        let mut wrong_header = HEADER; wrong_header[0] ^= 1;
        assert!(matches!(decrypt_content(
            &mut Cursor::new(&encrypted), &mut Vec::new(), plaintext.len() as u64,
            count, &context(&MASTER_KEY, &FILE_ID, &wrong_header),
        ), Err(ContentCryptoError::AuthenticationFailed(0))));

        let mut wrong_id = FILE_ID; wrong_id[0] ^= 1;
        assert!(matches!(decrypt_content(
            &mut Cursor::new(&encrypted), &mut Vec::new(), plaintext.len() as u64,
            count, &context(&MASTER_KEY, &wrong_id, &HEADER),
        ), Err(ContentCryptoError::AuthenticationFailed(0))));

        let mut swapped = encrypted.clone();
        let (first, rest) = swapped.split_at_mut(STORED_CHUNK_LENGTH);
        first.swap_with_slice(&mut rest[..STORED_CHUNK_LENGTH]);
        assert!(matches!(decrypt_content(
            &mut Cursor::new(swapped), &mut Vec::new(), plaintext.len() as u64,
            count, &context(&MASTER_KEY, &FILE_ID, &HEADER),
        ), Err(ContentCryptoError::AuthenticationFailed(0))));
    }

    #[test]
    fn truncation_trailing_data_and_count_mismatch_are_rejected() {
        let plaintext = b"exact bytes".to_vec();
        let mut encrypted = Vec::new();
        encrypt_content(
            &mut Cursor::new(&plaintext), &mut encrypted, plaintext.len() as u64,
            &context(&MASTER_KEY, &FILE_ID, &HEADER),
        ).unwrap();

        assert!(matches!(decrypt_content(
            &mut Cursor::new(&encrypted[..encrypted.len() - 1]), &mut Vec::new(),
            plaintext.len() as u64, 1, &context(&MASTER_KEY, &FILE_ID, &HEADER),
        ), Err(ContentCryptoError::TruncatedCiphertext)));

        let mut trailing = encrypted.clone(); trailing.push(0);
        assert!(matches!(decrypt_content(
            &mut Cursor::new(trailing), &mut Vec::new(), plaintext.len() as u64,
            1, &context(&MASTER_KEY, &FILE_ID, &HEADER),
        ), Err(ContentCryptoError::TrailingCiphertext)));

        assert!(matches!(decrypt_content(
            &mut Cursor::new(encrypted), &mut Vec::new(), plaintext.len() as u64,
            2, &context(&MASTER_KEY, &FILE_ID, &HEADER),
        ), Err(ContentCryptoError::ChunkCountMismatch)));

        assert!(matches!(encrypt_content(
            &mut Cursor::new(b"too short"), &mut Vec::new(), 100,
            &context(&MASTER_KEY, &FILE_ID, &HEADER),
        ), Err(ContentCryptoError::TruncatedPlaintext)));
        assert!(matches!(encrypt_content(
            &mut Cursor::new(b"trailing"), &mut Vec::new(), 1,
            &context(&MASTER_KEY, &FILE_ID, &HEADER),
        ), Err(ContentCryptoError::TrailingPlaintext)));
    }

    #[test]
    fn nonce_layout_is_prefix_plus_little_endian_index() {
        assert_eq!(content_nonce(&NONCE_PREFIX, 0), [0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0, 0, 0, 0]);
        assert_eq!(content_nonce(&NONCE_PREFIX, 0x01020304), [0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 4, 3, 2, 1]);
    }
}
