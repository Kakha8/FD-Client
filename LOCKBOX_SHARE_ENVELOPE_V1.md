# Lockbox Recipient Share Envelope V1

This document defines the cryptographic recipient-DEK envelope implemented by
`native-rust/src/share_envelope.rs`. It is a prerequisite for, but is not by
itself, a complete signed sharing grant.

All integers are unsigned little-endian unless explicitly stated. UUIDs are
the canonical 16 RFC 4122 bytes, not strings and not Java database IDs.

## Suite

```text
shareEnvelopeVersion = 1
suiteId = 1
KEM = ML-KEM-1024
KDF = HKDF-SHA3-512
wrap AEAD = AES-256-GCM
file master key = 32 bytes
salt = 32 bytes
nonce = 12 bytes
KEM ciphertext = 1,568 bytes
wrapped file master key = 48 bytes including GCM tag
permission READ = 1
expiresAtUnixSeconds = 0 means no expiry
```

## Canonical envelope context

The context is exactly 182 bytes:

| Size | Field |
|---:|---|
| 2 | shareEnvelopeVersion = 1 |
| 2 | suiteId = 1 |
| 16 | shareId UUID |
| 16 | clientFileId UUID |
| 8 | revision, at least 1 |
| 64 | SHA3-512 complete-container hash |
| 16 | owner account public UUID |
| 16 | recipient account public UUID |
| 32 | recipient ML-KEM encryption key ID |
| 2 | permission, READ = 1 |
| 8 | expiresAtUnixSeconds, 0 for none |

The owner and recipient UUIDs must differ.

## Wrapping

1. Confirm `recipientEncryptionKeyId` equals
   `SHA3-256(canonical recipient ML-KEM public key)`.
2. ML-KEM-1024 encapsulate to the recipient public key.
3. Generate a fresh 32-byte `wrapSalt` and 12-byte `wrapNonce`.
4. Derive the 32-byte wrapping key:

```text
PRK = HKDF-Extract-SHA3-512(
    salt = wrapSalt,
    IKM = ML-KEM shared secret
)

wrapKey = HKDF-Expand-SHA3-512(
    PRK,
    "FD-CSE-V3-SHARE-WRAP-KEY-V1\0" || canonicalContext,
    32
)
```

5. Construct AES-GCM AAD:

```text
"FD-CSE-V3-SHARE-ENVELOPE-V1\0"
|| canonicalContext
|| wrapSalt
|| SHA3-512(mlKemCiphertext)
```

6. AES-256-GCM encrypt the existing 32-byte file master key.

The public envelope contains:

```text
wrapSalt
wrapNonce
mlKemCiphertext
wrappedFileMasterKey
```

The ML-KEM shared secret, derived wrapping key, and plaintext file master key
must be zeroized when their lifetimes end.

## Security boundary

This envelope is not authorization by itself. The future `ShareGrantV1`
canonical record must include the complete canonical context and all four
envelope fields and must be signed by the owner's ML-DSA-87 key. The backend
must not activate a share until that signature contract is implemented and
verified.

