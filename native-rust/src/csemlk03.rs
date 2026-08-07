use thiserror::Error;

pub const MAGIC: &[u8; 8] = b"CSEMLK03";
pub const MANIFEST_MAGIC: &[u8; 8] = b"FDMAN003";
pub const SIGNATURE_MAGIC: &[u8; 8] = b"FDSIG001";
pub const FORMAT_VERSION: u16 = 3;
pub const SUITE_ID: u16 = 1;
pub const FIXED_HEADER_LENGTH: usize = 32;
pub const MAX_HEADER_LENGTH: usize = 1024 * 1024;
pub const CHUNK_SIZE: u32 = 1_048_576;
pub const REQUIRED_FLAGS: u16 = 0x0001 | 0x0002 | 0x0004;
pub const SECTION_CRITICAL: u16 = 0x0001;
pub const CONTENT_PARAMETERS: u16 = 0x0001;
pub const OWNER_KEY_ENVELOPE: u16 = 0x0002;
pub const ENCRYPTED_METADATA: u16 = 0x0003;
pub const ML_KEM_1024_CIPHERTEXT_LENGTH: usize = 1_568;
pub const WRAPPED_FILE_MASTER_KEY_LENGTH: usize = 32 + 16;
pub const ML_DSA_87_SIGNATURE_LENGTH: usize = 4_627;
pub const MANIFEST_LENGTH: usize = 264;
pub const MAX_METADATA_PLAINTEXT_LENGTH: usize = 64 * 1024;
pub const MANIFEST_SIGNING_DOMAIN: &[u8] = b"FD-LOCKBOX-MANIFEST-V1\0";

pub fn expected_container_size(
    total_header_length: usize,
    chunk_count: u32,
) -> Result<u64, FormatError> {
    if chunk_count == 0 { return Err(FormatError::InvalidChunkCount); }
    let stored_chunk_size = u64::from(CHUNK_SIZE).checked_add(16).ok_or(FormatError::SizeOverflow)?;
    u64::try_from(total_header_length).map_err(|_| FormatError::SizeOverflow)?
        .checked_add(u64::from(chunk_count).checked_mul(stored_chunk_size).ok_or(FormatError::SizeOverflow)?)
        .ok_or(FormatError::SizeOverflow)
}

pub fn manifest_signing_message(manifest_bytes: &[u8]) -> Result<Vec<u8>, FormatError> {
    if manifest_bytes.len() != MANIFEST_LENGTH { return Err(FormatError::InvalidManifest); }
    let mut message = Vec::with_capacity(MANIFEST_SIGNING_DOMAIN.len() + MANIFEST_LENGTH);
    message.extend_from_slice(MANIFEST_SIGNING_DOMAIN);
    message.extend_from_slice(manifest_bytes);
    Ok(message)
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FormatError {
    #[error("input is truncated")]
    Truncated,
    #[error("unexpected trailing data")]
    TrailingData,
    #[error("invalid magic")]
    InvalidMagic,
    #[error("unsupported format version")]
    UnsupportedVersion,
    #[error("unsupported cryptographic suite")]
    UnsupportedSuite,
    #[error("invalid fixed header length")]
    InvalidFixedHeaderLength,
    #[error("invalid total header length")]
    InvalidTotalHeaderLength,
    #[error("unsupported flags")]
    UnsupportedFlags,
    #[error("invalid chunk size")]
    InvalidChunkSize,
    #[error("chunk count must be at least one")]
    InvalidChunkCount,
    #[error("invalid section count")]
    InvalidSectionCount,
    #[error("reserved field must be zero")]
    NonZeroReserved,
    #[error("invalid section type or order")]
    InvalidSectionOrder,
    #[error("invalid section flags")]
    InvalidSectionFlags,
    #[error("invalid section payload length")]
    InvalidSectionLength,
    #[error("invalid algorithm identifier")]
    InvalidAlgorithm,
    #[error("invalid authentication tag size")]
    InvalidTagSize,
    #[error("metadata is invalid")]
    InvalidMetadata,
    #[error("metadata text is not valid UTF-8")]
    InvalidUtf8,
    #[error("unsafe output filename")]
    UnsafeFilename,
    #[error("numeric size overflow")]
    SizeOverflow,
    #[error("invalid manifest")]
    InvalidManifest,
    #[error("invalid signature record")]
    InvalidSignatureRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentParametersData {
    pub client_file_id: [u8; 16],
    pub file_kdf_salt: [u8; 32],
    pub content_nonce_prefix: [u8; 8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerKeyEnvelopeData {
    pub recipient_encryption_key_id: [u8; 32],
    pub wrap_salt: [u8; 32],
    pub wrap_nonce: [u8; 12],
    pub kem_ciphertext: Vec<u8>,
    pub wrapped_file_master_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedMetadataData {
    pub metadata_nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub chunk_count: u32,
    pub content_parameters: ContentParametersData,
    pub owner_envelope: OwnerKeyEnvelopeData,
    pub encrypted_metadata: EncryptedMetadataData,
}

impl Header {
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        if self.chunk_count == 0 {
            return Err(FormatError::InvalidChunkCount);
        }
        let content = encode_content_parameters(&self.content_parameters);
        let envelope = encode_owner_envelope(&self.owner_envelope)?;
        let metadata = encode_encrypted_metadata(&self.encrypted_metadata)?;
        let total = FIXED_HEADER_LENGTH
            .checked_add(content.len())
            .and_then(|v| v.checked_add(envelope.len()))
            .and_then(|v| v.checked_add(metadata.len()))
            .ok_or(FormatError::SizeOverflow)?;
        if total > MAX_HEADER_LENGTH {
            return Err(FormatError::InvalidTotalHeaderLength);
        }

        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(MAGIC);
        put_u16(&mut out, FORMAT_VERSION);
        put_u16(&mut out, FIXED_HEADER_LENGTH as u16);
        put_u32(&mut out, u32::try_from(total).map_err(|_| FormatError::SizeOverflow)?);
        put_u16(&mut out, SUITE_ID);
        put_u16(&mut out, REQUIRED_FLAGS);
        put_u32(&mut out, CHUNK_SIZE);
        put_u32(&mut out, self.chunk_count);
        put_u16(&mut out, 3);
        put_u16(&mut out, 0);
        out.extend_from_slice(&content);
        out.extend_from_slice(&envelope);
        out.extend_from_slice(&metadata);
        Ok(out)
    }

    pub fn parse(input: &[u8]) -> Result<Self, FormatError> {
        if input.len() < FIXED_HEADER_LENGTH {
            return Err(FormatError::Truncated);
        }
        if &input[0..8] != MAGIC {
            return Err(FormatError::InvalidMagic);
        }
        if read_u16(input, 8)? != FORMAT_VERSION {
            return Err(FormatError::UnsupportedVersion);
        }
        if read_u16(input, 10)? as usize != FIXED_HEADER_LENGTH {
            return Err(FormatError::InvalidFixedHeaderLength);
        }
        let total = read_u32(input, 12)? as usize;
        if !(FIXED_HEADER_LENGTH..=MAX_HEADER_LENGTH).contains(&total) {
            return Err(FormatError::InvalidTotalHeaderLength);
        }
        if input.len() < total {
            return Err(FormatError::Truncated);
        }
        if input.len() > total {
            return Err(FormatError::TrailingData);
        }
        if read_u16(input, 16)? != SUITE_ID {
            return Err(FormatError::UnsupportedSuite);
        }
        if read_u16(input, 18)? != REQUIRED_FLAGS {
            return Err(FormatError::UnsupportedFlags);
        }
        if read_u32(input, 20)? != CHUNK_SIZE {
            return Err(FormatError::InvalidChunkSize);
        }
        let chunk_count = read_u32(input, 24)?;
        if chunk_count == 0 {
            return Err(FormatError::InvalidChunkCount);
        }
        if read_u16(input, 28)? != 3 {
            return Err(FormatError::InvalidSectionCount);
        }
        if read_u16(input, 30)? != 0 {
            return Err(FormatError::NonZeroReserved);
        }

        let mut cursor = FIXED_HEADER_LENGTH;
        let content_payload = section(input, &mut cursor, CONTENT_PARAMETERS)?;
        let envelope_payload = section(input, &mut cursor, OWNER_KEY_ENVELOPE)?;
        let metadata_payload = section(input, &mut cursor, ENCRYPTED_METADATA)?;
        if cursor != total {
            return Err(FormatError::TrailingData);
        }
        Ok(Self {
            chunk_count,
            content_parameters: parse_content_parameters(content_payload)?,
            owner_envelope: parse_owner_envelope(envelope_payload)?,
            encrypted_metadata: parse_encrypted_metadata(metadata_payload)?,
        })
    }
}

fn encode_content_parameters(value: &ContentParametersData) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(&value.client_file_id);
    payload.extend_from_slice(&value.file_kdf_salt);
    payload.extend_from_slice(&value.content_nonce_prefix);
    put_u16(&mut payload, 16);
    put_u16(&mut payload, 16);
    put_u32(&mut payload, 0);
    frame(CONTENT_PARAMETERS, &payload).expect("fixed content section length fits u32")
}

fn parse_content_parameters(input: &[u8]) -> Result<ContentParametersData, FormatError> {
    if input.len() != 64 {
        return Err(FormatError::InvalidSectionLength);
    }
    if read_u16(input, 56)? != 16 || read_u16(input, 58)? != 16 {
        return Err(FormatError::InvalidTagSize);
    }
    if read_u32(input, 60)? != 0 {
        return Err(FormatError::NonZeroReserved);
    }
    Ok(ContentParametersData {
        client_file_id: array(input, 0)?,
        file_kdf_salt: array(input, 16)?,
        content_nonce_prefix: array(input, 48)?,
    })
}

fn encode_owner_envelope(value: &OwnerKeyEnvelopeData) -> Result<Vec<u8>, FormatError> {
    if value.kem_ciphertext.len() != ML_KEM_1024_CIPHERTEXT_LENGTH
        || value.wrapped_file_master_key.len() != WRAPPED_FILE_MASTER_KEY_LENGTH
    {
        return Err(FormatError::InvalidSectionLength);
    }
    let mut payload = Vec::with_capacity(92 + value.kem_ciphertext.len() + value.wrapped_file_master_key.len());
    payload.extend_from_slice(&value.recipient_encryption_key_id);
    put_u16(&mut payload, 1);
    put_u16(&mut payload, 1);
    put_u16(&mut payload, 1);
    put_u16(&mut payload, 0);
    payload.extend_from_slice(&value.wrap_salt);
    payload.extend_from_slice(&value.wrap_nonce);
    put_u32(&mut payload, value.kem_ciphertext.len() as u32);
    put_u32(&mut payload, value.wrapped_file_master_key.len() as u32);
    payload.extend_from_slice(&value.kem_ciphertext);
    payload.extend_from_slice(&value.wrapped_file_master_key);
    frame(OWNER_KEY_ENVELOPE, &payload)
}

fn parse_owner_envelope(input: &[u8]) -> Result<OwnerKeyEnvelopeData, FormatError> {
    if input.len() < 92 {
        return Err(FormatError::Truncated);
    }
    if read_u16(input, 32)? != 1 || read_u16(input, 34)? != 1 || read_u16(input, 36)? != 1 {
        return Err(FormatError::InvalidAlgorithm);
    }
    if read_u16(input, 38)? != 0 {
        return Err(FormatError::NonZeroReserved);
    }
    let kem_len = read_u32(input, 84)? as usize;
    let wrapped_len = read_u32(input, 88)? as usize;
    if kem_len != ML_KEM_1024_CIPHERTEXT_LENGTH || wrapped_len != WRAPPED_FILE_MASTER_KEY_LENGTH {
        return Err(FormatError::InvalidSectionLength);
    }
    let end = 92usize.checked_add(kem_len).and_then(|v| v.checked_add(wrapped_len))
        .ok_or(FormatError::SizeOverflow)?;
    if input.len() < end { return Err(FormatError::Truncated); }
    if input.len() > end { return Err(FormatError::TrailingData); }
    Ok(OwnerKeyEnvelopeData {
        recipient_encryption_key_id: array(input, 0)?,
        wrap_salt: array(input, 40)?,
        wrap_nonce: array(input, 72)?,
        kem_ciphertext: input[92..92 + kem_len].to_vec(),
        wrapped_file_master_key: input[92 + kem_len..end].to_vec(),
    })
}

fn encode_encrypted_metadata(value: &EncryptedMetadataData) -> Result<Vec<u8>, FormatError> {
    if value.ciphertext.len() < 16 || value.ciphertext.len() > MAX_METADATA_PLAINTEXT_LENGTH + 16 {
        return Err(FormatError::InvalidSectionLength);
    }
    let mut payload = Vec::with_capacity(16 + value.ciphertext.len());
    payload.extend_from_slice(&value.metadata_nonce);
    put_u32(&mut payload, value.ciphertext.len() as u32);
    payload.extend_from_slice(&value.ciphertext);
    frame(ENCRYPTED_METADATA, &payload)
}

fn parse_encrypted_metadata(input: &[u8]) -> Result<EncryptedMetadataData, FormatError> {
    if input.len() < 32 { return Err(FormatError::Truncated); }
    let length = read_u32(input, 12)? as usize;
    if length < 16 || length > MAX_METADATA_PLAINTEXT_LENGTH + 16 {
        return Err(FormatError::InvalidSectionLength);
    }
    let end = 16usize.checked_add(length).ok_or(FormatError::SizeOverflow)?;
    if input.len() < end { return Err(FormatError::Truncated); }
    if input.len() > end { return Err(FormatError::TrailingData); }
    Ok(EncryptedMetadataData { metadata_nonce: array(input, 0)?, ciphertext: input[16..end].to_vec() })
}

fn frame(section_type: u16, payload: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut out = Vec::with_capacity(8 + payload.len());
    put_u16(&mut out, section_type);
    put_u16(&mut out, SECTION_CRITICAL);
    put_u32(&mut out, u32::try_from(payload.len()).map_err(|_| FormatError::SizeOverflow)?);
    out.extend_from_slice(payload);
    Ok(out)
}

fn section<'a>(input: &'a [u8], cursor: &mut usize, expected: u16) -> Result<&'a [u8], FormatError> {
    let header_end = cursor.checked_add(8).ok_or(FormatError::SizeOverflow)?;
    if header_end > input.len() { return Err(FormatError::Truncated); }
    if read_u16(input, *cursor)? != expected { return Err(FormatError::InvalidSectionOrder); }
    if read_u16(input, *cursor + 2)? != SECTION_CRITICAL { return Err(FormatError::InvalidSectionFlags); }
    let length = read_u32(input, *cursor + 4)? as usize;
    let end = header_end.checked_add(length).ok_or(FormatError::SizeOverflow)?;
    if end > input.len() { return Err(FormatError::Truncated); }
    *cursor = end;
    Ok(&input[header_end..end])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub client_file_id: [u8; 16],
    pub revision: u64,
    pub exact_plaintext_size: u64,
    pub created_at_unix_millis: i64,
    pub modified_at_unix_millis: i64,
    pub filename: String,
    pub mime_type: String,
}

impl Metadata {
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        validate_filename(&self.filename)?;
        if self.revision == 0 { return Err(FormatError::InvalidMetadata); }
        let filename = self.filename.as_bytes();
        let mime = self.mime_type.as_bytes();
        if filename.len() > 1024 || mime.len() > 255 { return Err(FormatError::InvalidMetadata); }
        let total = 56usize.checked_add(filename.len()).and_then(|v| v.checked_add(mime.len()))
            .ok_or(FormatError::SizeOverflow)?;
        if total > MAX_METADATA_PLAINTEXT_LENGTH { return Err(FormatError::InvalidMetadata); }
        let mut out = Vec::with_capacity(total);
        put_u16(&mut out, 1); put_u16(&mut out, 0);
        out.extend_from_slice(&self.client_file_id);
        put_u64(&mut out, self.revision); put_u64(&mut out, self.exact_plaintext_size);
        put_i64(&mut out, self.created_at_unix_millis); put_i64(&mut out, self.modified_at_unix_millis);
        put_u16(&mut out, filename.len() as u16); put_u16(&mut out, mime.len() as u16);
        out.extend_from_slice(filename); out.extend_from_slice(mime);
        Ok(out)
    }

    pub fn parse(input: &[u8]) -> Result<Self, FormatError> {
        if input.len() < 56 { return Err(FormatError::Truncated); }
        if input.len() > MAX_METADATA_PLAINTEXT_LENGTH { return Err(FormatError::InvalidMetadata); }
        if read_u16(input, 0)? != 1 || read_u16(input, 2)? != 0 { return Err(FormatError::InvalidMetadata); }
        let revision = read_u64(input, 20)?;
        if revision == 0 { return Err(FormatError::InvalidMetadata); }
        let filename_len = read_u16(input, 52)? as usize;
        let mime_len = read_u16(input, 54)? as usize;
        if filename_len > 1024 || mime_len > 255 { return Err(FormatError::InvalidMetadata); }
        let filename_end = 56usize.checked_add(filename_len).ok_or(FormatError::SizeOverflow)?;
        let end = filename_end.checked_add(mime_len).ok_or(FormatError::SizeOverflow)?;
        if input.len() < end { return Err(FormatError::Truncated); }
        if input.len() > end { return Err(FormatError::TrailingData); }
        let filename = std::str::from_utf8(&input[56..filename_end]).map_err(|_| FormatError::InvalidUtf8)?.to_owned();
        let mime_type = std::str::from_utf8(&input[filename_end..end]).map_err(|_| FormatError::InvalidUtf8)?.to_owned();
        validate_filename(&filename)?;
        Ok(Self {
            client_file_id: array(input, 4)?, revision,
            exact_plaintext_size: read_u64(input, 28)?,
            created_at_unix_millis: read_i64(input, 36)?,
            modified_at_unix_millis: read_i64(input, 44)?, filename, mime_type,
        })
    }
}

fn validate_filename(value: &str) -> Result<(), FormatError> {
    if value.is_empty() || value == "." || value == ".." || value.contains('\0')
        || value.contains('/') || value.contains('\\') || value.starts_with('/')
        || (value.len() >= 2 && value.as_bytes()[1] == b':')
    { return Err(FormatError::UnsafeFilename); }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub client_file_id: [u8; 16], pub revision: u64, pub container_size: u64,
    pub container_hash: [u8; 64], pub owner_encryption_key_id: [u8; 32],
    pub signing_key_id: [u8; 32], pub device_id: [u8; 16],
    pub created_at_unix_millis: i64, pub previous_manifest_hash: [u8; 64],
}

impl Manifest {
    pub fn encode(&self) -> Result<[u8; MANIFEST_LENGTH], FormatError> {
        if self.revision == 0 { return Err(FormatError::InvalidManifest); }
        validate_manifest_chain(self.revision, &self.previous_manifest_hash)?;
        let mut out = Vec::with_capacity(MANIFEST_LENGTH);
        out.extend_from_slice(MANIFEST_MAGIC); put_u16(&mut out, 1); put_u16(&mut out, 3);
        put_u16(&mut out, 1); put_u16(&mut out, 1); out.extend_from_slice(&self.client_file_id);
        put_u64(&mut out, self.revision); put_u64(&mut out, self.container_size);
        out.extend_from_slice(&self.container_hash); out.extend_from_slice(&self.owner_encryption_key_id);
        out.extend_from_slice(&self.signing_key_id); out.extend_from_slice(&self.device_id);
        put_i64(&mut out, self.created_at_unix_millis); out.extend_from_slice(&self.previous_manifest_hash);
        out.try_into().map_err(|_| FormatError::InvalidManifest)
    }

    pub fn parse(input: &[u8]) -> Result<Self, FormatError> {
        if input.len() < MANIFEST_LENGTH { return Err(FormatError::Truncated); }
        if input.len() > MANIFEST_LENGTH { return Err(FormatError::TrailingData); }
        if &input[0..8] != MANIFEST_MAGIC { return Err(FormatError::InvalidMagic); }
        if read_u16(input, 8)? != 1 || read_u16(input, 10)? != 3 { return Err(FormatError::UnsupportedVersion); }
        if read_u16(input, 12)? != 1 { return Err(FormatError::UnsupportedSuite); }
        if read_u16(input, 14)? != 1 { return Err(FormatError::InvalidAlgorithm); }
        let revision = read_u64(input, 32)?;
        if revision == 0 { return Err(FormatError::InvalidManifest); }
        let previous_manifest_hash = array(input, 200)?;
        validate_manifest_chain(revision, &previous_manifest_hash)?;
        Ok(Self { client_file_id: array(input, 16)?, revision, container_size: read_u64(input, 40)?,
            container_hash: array(input, 48)?, owner_encryption_key_id: array(input, 112)?,
            signing_key_id: array(input, 144)?, device_id: array(input, 176)?,
            created_at_unix_millis: read_i64(input, 192)?, previous_manifest_hash })
    }
}

fn validate_manifest_chain(revision: u64, previous_hash: &[u8; 64]) -> Result<(), FormatError> {
    let is_zero = previous_hash.iter().all(|byte| *byte == 0);
    if (revision == 1 && !is_zero) || (revision > 1 && is_zero) {
        return Err(FormatError::InvalidManifest);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureRecord { pub signing_key_id: [u8; 32], pub signature: Vec<u8> }

impl SignatureRecord {
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        if self.signature.len() != ML_DSA_87_SIGNATURE_LENGTH { return Err(FormatError::InvalidSignatureRecord); }
        let mut out = Vec::with_capacity(48 + self.signature.len());
        out.extend_from_slice(SIGNATURE_MAGIC); put_u16(&mut out, 1); put_u16(&mut out, 1);
        out.extend_from_slice(&self.signing_key_id); put_u32(&mut out, self.signature.len() as u32);
        out.extend_from_slice(&self.signature); Ok(out)
    }
    pub fn parse(input: &[u8]) -> Result<Self, FormatError> {
        if input.len() < 48 { return Err(FormatError::Truncated); }
        if &input[0..8] != SIGNATURE_MAGIC { return Err(FormatError::InvalidMagic); }
        if read_u16(input, 8)? != 1 { return Err(FormatError::UnsupportedVersion); }
        if read_u16(input, 10)? != 1 { return Err(FormatError::InvalidAlgorithm); }
        let length = read_u32(input, 44)? as usize;
        if length != ML_DSA_87_SIGNATURE_LENGTH { return Err(FormatError::InvalidSignatureRecord); }
        let end = 48usize.checked_add(length).ok_or(FormatError::SizeOverflow)?;
        if input.len() < end { return Err(FormatError::Truncated); }
        if input.len() > end { return Err(FormatError::TrailingData); }
        Ok(Self { signing_key_id: array(input, 12)?, signature: input[48..end].to_vec() })
    }
}

fn array<const N: usize>(input: &[u8], offset: usize) -> Result<[u8; N], FormatError> {
    let end = offset.checked_add(N).ok_or(FormatError::SizeOverflow)?;
    input.get(offset..end).ok_or(FormatError::Truncated)?.try_into().map_err(|_| FormatError::Truncated)
}
fn read_u16(i: &[u8], o: usize) -> Result<u16, FormatError> { Ok(u16::from_le_bytes(array(i, o)?)) }
fn read_u32(i: &[u8], o: usize) -> Result<u32, FormatError> { Ok(u32::from_le_bytes(array(i, o)?)) }
fn read_u64(i: &[u8], o: usize) -> Result<u64, FormatError> { Ok(u64::from_le_bytes(array(i, o)?)) }
fn read_i64(i: &[u8], o: usize) -> Result<i64, FormatError> { Ok(i64::from_le_bytes(array(i, o)?)) }
fn put_u16(o: &mut Vec<u8>, v: u16) { o.extend_from_slice(&v.to_le_bytes()); }
fn put_u32(o: &mut Vec<u8>, v: u32) { o.extend_from_slice(&v.to_le_bytes()); }
fn put_u64(o: &mut Vec<u8>, v: u64) { o.extend_from_slice(&v.to_le_bytes()); }
fn put_i64(o: &mut Vec<u8>, v: i64) { o.extend_from_slice(&v.to_le_bytes()); }

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Header {
        Header { chunk_count: 2,
            content_parameters: ContentParametersData { client_file_id: [1; 16], file_kdf_salt: [2; 32], content_nonce_prefix: [3; 8] },
            owner_envelope: OwnerKeyEnvelopeData { recipient_encryption_key_id: [4; 32], wrap_salt: [5; 32], wrap_nonce: [6; 12], kem_ciphertext: vec![7; ML_KEM_1024_CIPHERTEXT_LENGTH], wrapped_file_master_key: vec![8; WRAPPED_FILE_MASTER_KEY_LENGTH] },
            encrypted_metadata: EncryptedMetadataData { metadata_nonce: [9; 12], ciphertext: vec![10; 72] } }
    }

    #[test]
    fn header_round_trip() {
        let value = header(); let encoded = value.encode().unwrap();
        assert_eq!(read_u32(&encoded, 12).unwrap() as usize, encoded.len());
        assert_eq!(Header::parse(&encoded).unwrap(), value);
    }

    #[test]
    fn header_rejects_invalid_preamble_and_sections() {
        let encoded = header().encode().unwrap();
        let cases = [
            (0, vec![0], FormatError::InvalidMagic),
            (10, 31u16.to_le_bytes().to_vec(), FormatError::InvalidFixedHeaderLength),
            (18, 0u16.to_le_bytes().to_vec(), FormatError::UnsupportedFlags),
            (20, 1u32.to_le_bytes().to_vec(), FormatError::InvalidChunkSize),
            (24, 0u32.to_le_bytes().to_vec(), FormatError::InvalidChunkCount),
            (28, 2u16.to_le_bytes().to_vec(), FormatError::InvalidSectionCount),
            (30, 1u16.to_le_bytes().to_vec(), FormatError::NonZeroReserved),
        ];
        for (offset, replacement, error) in cases {
            let mut bad = encoded.clone();
            bad[offset..offset + replacement.len()].copy_from_slice(&replacement);
            assert_eq!(Header::parse(&bad).unwrap_err(), error);
        }
        let mut wrong_order = encoded.clone(); wrong_order[32] = 2;
        assert_eq!(Header::parse(&wrong_order).unwrap_err(), FormatError::InvalidSectionOrder);
        let mut invalid_section_flags = encoded.clone(); invalid_section_flags[34] = 0;
        assert_eq!(Header::parse(&invalid_section_flags).unwrap_err(), FormatError::InvalidSectionFlags);
        assert_eq!(Header::parse(&encoded[..encoded.len() - 1]).unwrap_err(), FormatError::Truncated);
        let mut trailing = encoded.clone(); trailing.push(0);
        assert_eq!(Header::parse(&trailing).unwrap_err(), FormatError::TrailingData);
    }

    #[test]
    fn header_rejects_unsupported_version_suite_and_invalid_total_length() {
        let encoded = header().encode().unwrap();
        let mut bad_version = encoded.clone(); bad_version[8..10].copy_from_slice(&4u16.to_le_bytes());
        assert_eq!(Header::parse(&bad_version).unwrap_err(), FormatError::UnsupportedVersion);
        let mut bad_suite = encoded.clone(); bad_suite[16..18].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(Header::parse(&bad_suite).unwrap_err(), FormatError::UnsupportedSuite);
        let mut too_small = encoded.clone(); too_small[12..16].copy_from_slice(&31u32.to_le_bytes());
        assert_eq!(Header::parse(&too_small).unwrap_err(), FormatError::InvalidTotalHeaderLength);
        let mut too_large = encoded; too_large[12..16].copy_from_slice(&((MAX_HEADER_LENGTH + 1) as u32).to_le_bytes());
        assert_eq!(Header::parse(&too_large).unwrap_err(), FormatError::InvalidTotalHeaderLength);
    }

    #[test]
    fn expected_container_size_is_checked_and_includes_tags() {
        assert_eq!(expected_container_size(100, 2).unwrap(), 100 + 2 * (1_048_576 + 16));
        assert_eq!(expected_container_size(100, 0).unwrap_err(), FormatError::InvalidChunkCount);
    }

    #[test]
    fn metadata_round_trip_and_unsafe_names() {
        let value = Metadata { client_file_id: [11; 16], revision: 1, exact_plaintext_size: 42,
            created_at_unix_millis: -1, modified_at_unix_millis: 2,
            filename: "hello.txt".into(), mime_type: "text/plain".into() };
        assert_eq!(Metadata::parse(&value.encode().unwrap()).unwrap(), value);
        for name in ["", ".", "..", "a/b", "a\\b", "C:file", "bad\0name"] {
            let mut bad = value.clone(); bad.filename = name.into();
            assert_eq!(bad.encode().unwrap_err(), FormatError::UnsafeFilename);
        }
        let mut invalid_utf8 = value.encode().unwrap(); invalid_utf8[56] = 0xff;
        assert_eq!(Metadata::parse(&invalid_utf8).unwrap_err(), FormatError::InvalidUtf8);
    }

    #[test]
    fn manifest_is_exact_and_round_trips() {
        let value = Manifest { client_file_id: [1; 16], revision: 1, container_size: 99,
            container_hash: [2; 64], owner_encryption_key_id: [3; 32], signing_key_id: [4; 32],
            device_id: [5; 16], created_at_unix_millis: 123, previous_manifest_hash: [0; 64] };
        let encoded = value.encode().unwrap();
        assert_eq!(encoded.len(), MANIFEST_LENGTH);
        assert_eq!(Manifest::parse(&encoded).unwrap(), value);
        let message = manifest_signing_message(&encoded).unwrap();
        assert_eq!(&message[..MANIFEST_SIGNING_DOMAIN.len()], MANIFEST_SIGNING_DOMAIN);
        assert_eq!(&message[MANIFEST_SIGNING_DOMAIN.len()..], &encoded);
        assert_eq!(Manifest::parse(&encoded[..263]).unwrap_err(), FormatError::Truncated);

        let mut invalid_chain = value.clone(); invalid_chain.previous_manifest_hash = [1; 64];
        assert_eq!(invalid_chain.encode().unwrap_err(), FormatError::InvalidManifest);
        invalid_chain.revision = 2; invalid_chain.previous_manifest_hash = [0; 64];
        assert_eq!(invalid_chain.encode().unwrap_err(), FormatError::InvalidManifest);
    }

    #[test]
    fn signature_record_round_trip_and_length_checks() {
        let value = SignatureRecord { signing_key_id: [8; 32], signature: vec![9; ML_DSA_87_SIGNATURE_LENGTH] };
        let encoded = value.encode().unwrap();
        assert_eq!(SignatureRecord::parse(&encoded).unwrap(), value);
        assert_eq!(SignatureRecord::parse(&encoded[..encoded.len() - 1]).unwrap_err(), FormatError::Truncated);
        let mut trailing = encoded; trailing.push(0);
        assert_eq!(SignatureRecord::parse(&trailing).unwrap_err(), FormatError::TrailingData);
    }
}
