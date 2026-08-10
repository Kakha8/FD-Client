# Task: Implement the CSEMLK03 Lockbox upload backend

Work in the `File-Drive-Spring` backend repository. Implement the backend changes needed to accept, validate, store, list, and download the three artifacts produced by the v3 desktop client:

```text
<client-file-uuid>.fdcse
<client-file-uuid>.fdmanifest
<client-file-uuid>.fdsig
```

Read the architecture document completely before modifying code. Its exact absolute path is:

```text
C:\Users\Kakha\Downloads\CSEMLK03_CODEX_ARCHITECTURE.md
```

Do not limit the search to the backend repository, client repository, or Codex attachments; the document is in the user's Downloads directory. Also inspect the actual v3 Rust encoders in `C:\git-repos\FD-Client\native-rust\src`, especially:

```text
csemlk03.rs
v3_artifacts.rs
```

The Rust implementation is the current source of truth for the bytes emitted by the client. Do not guess offsets, lengths, algorithms, domain separators, endianness, or key-ID derivation. If the architecture document and implementation disagree, stop and report the discrepancy instead of silently choosing one.

## Existing functionality that must remain working

Keep the completed enrollment implementation and its behavior:

- `LockboxProfile`
- `LockboxDevice`
- `LockboxKey`
- `LockboxEnrollmentChallenge`
- their repositories
- `LockboxEnrollmentService`
- `LockboxEnrollmentController`
- `LockboxEnrollmentTranscript`
- `LockboxSignatureVerifier`
- status endpoint and enrollment endpoints

Keep existing authentication, current-user resolution, Lockbox folder ownership checks, Lockbox root creation, and MinIO integration where they remain applicable.

Do not store or request private encryption keys, private signing keys, file master keys, plaintext metadata, original filenames, MIME types, plaintext sizes, or decrypted content.

## Replace the legacy upload design

The current upload path accepts one CSEMLK02 file and uses a CSEMLK02-specific `LockboxContainerValidator`. It is incompatible with CSEMLK03.

Replace the single-file upload with a three-part multipart request:

```http
POST /api/lockbox/files
Content-Type: multipart/form-data
Authorization: Bearer <token>

container:  <uuid>.fdcse
manifest:   <uuid>.fdmanifest
signature:  <uuid>.fdsig
parentFolderId: optional request parameter
```

The controller should have the equivalent of:

```java
@PostMapping(
        value = "/files",
        consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
)
@ResponseStatus(HttpStatus.CREATED)
public LockboxUploadResponse upload(
        @RequestPart("container") MultipartFile container,
        @RequestPart("manifest") MultipartFile manifest,
        @RequestPart("signature") MultipartFile signature,
        @RequestParam(name = "parentFolderId", required = false)
        Long parentFolderId
) throws Exception
```

Do not accept the device UUID, client file UUID, revision, hashes, key IDs, suite, or timestamps as trusted JSON/form parameters. Obtain them from the signed binary manifest.

Multipart filenames are untrusted transport metadata. They may be checked for the expected extension and UUID basename, but must never override the values inside the signed manifest.

## Required v3 parser and validator classes

Replace the CSEMLK02 validator with focused components, using names consistent with this project, such as:

```text
LockboxManifestParser
LockboxSignatureRecordParser
LockboxV3ContainerValidator
LockboxV3UploadValidator
```

Use bounded binary parsing. Reject truncation, trailing bytes, integer overflow, unsupported flags, nonzero reserved fields, invalid section order/count/type/length, unsupported version/suite/algorithm identifiers, and sizes above configured limits. Never allocate a buffer based on an untrusted length until that length has been bounded.

Manifest and signature files are small and may be read into bounded byte arrays. The `.fdcse` container can be very large and must be staged and hashed using streaming I/O.

### Mandatory validation order

Perform upload validation in this order:

1. Authenticate and resolve the current user.
2. Require that the user's `LockboxProfile` is enabled.
3. Stage all three multipart parts in server-generated temporary files.
4. Enforce separate configured maximum sizes for container, manifest, and signature.
5. Read the exact manifest bytes without reserializing them.
6. Parse the signature record only far enough to obtain `signingKeyId`, while also validating its complete fixed structure.
7. Resolve `signingKeyId` to an active `LockboxKey` with role `SIGNING` and algorithm `ML_DSA_87`.
8. Require that the signing key's device is active, belongs to the authenticated user's profile, and has the same device UUID later declared by the manifest.
9. Verify ML-DSA-87 over the exact protocol signing transcript:

   ```text
   ASCII "FD-LOCKBOX-MANIFEST-V1\0"
   || exact .fdmanifest bytes
   ```

   Do not verify a JSON representation and do not introduce an extra pre-hash unless the protocol explicitly specifies a standardized ML-DSA pre-hash mode. Use the same Bouncy Castle ML-DSA-87 parameter set already used by enrollment verification.

10. Only after signature verification, fully parse and validate the manifest.
11. Require CSEMLK03/container version 3, manifest version 1, suite ID 1, and SHA3-512 hash algorithm ID 1.
12. Stream SHA3-512 over the complete staged `.fdcse` file.
13. Compare the actual container size and calculated hash with the signed manifest using constant-time byte comparison where appropriate.
14. Structurally parse the public CSEMLK03 preamble and header sections. Do not decrypt anything.
15. Cross-check the container and manifest values required by the protocol, including client file UUID, revision, suite, owner encryption key ID, chunk size/count, and any other duplicated public value.
16. Resolve the manifest/header encryption key ID to an active `LockboxKey` with role `ENCRYPTION` and algorithm `ML_KEM_1024` belonging to the same authenticated Lockbox profile.
17. Require the manifest device UUID to equal the active signing key's device UUID.
18. Initially accept only revision `1` and require `previousManifestHash` to be exactly 64 zero bytes. Return a clear validation error for later revisions until revision history is implemented.
19. Reject an already stored `(owner/profile, clientFileId, revision)` before object upload and enforce this uniqueness in the database as well.
20. Upload all three validated artifacts to object storage and persist their public metadata transactionally.

The server cannot validate AES-GCM content or encrypted metadata authentication because it has no private encryption key. It validates the signed public structure, exact container hash, registered keys, device/account binding, and protocol consistency.

## Database/model changes

Modify `LockboxFile`. Remove the legacy duplicated `encryptedMetadata` column because encrypted metadata already exists inside the `.fdcse` header.

Persist at least:

```text
clientFileId UUID
revision long
formatVersion int (3)
suiteId int (1), or a strict enum representing the exact v3 suite
containerSize long
containerHash byte[64]
encryptionKeyId byte[32]
signingKeyId byte[32]
deviceUuid UUID
containerObjectKey String
manifestObjectKey String
signatureObjectKey String
createdAt Instant
updatedAt Instant
```

Continue associating the logical Lockbox object with `FileMetaData` if that is required by the existing folder system. Do not put the private original filename in `FileMetaData`; the server does not know it. Use an opaque server display value such as:

```text
<clientFileId>.fdcse
```

Do not use the multipart original filename as the user's original filename.

Add a database uniqueness constraint that includes the owning Lockbox profile/user plus `clientFileId` and `revision`. If the existing shared-primary-key mapping prevents future revision history, document that this table stores the current revision and leave a clear path for a later `LockboxFileRevision` entity. Do not overbuild revision history in this task; accept only revision 1.

Update `LockboxFileRepository` with ownership-aware queries needed to reject duplicates and retrieve files safely. Avoid repository methods that compare binary key IDs incorrectly; verify how the configured database/JPA provider handles `byte[]`, or query by the owning key entity where possible.

Use a database migration if this project uses Flyway/Liquibase. Do not rely on destructive automatic schema recreation. Preserve unrelated user data and migrations.

## Object storage changes

Keep `LockboxObjectStorage` and `MinioLockboxObjectStorage`, but allow a caller-selected, allowlisted artifact content type, or expose explicit methods for each artifact type.

Store objects under deterministic, server-created keys similar to:

```text
users/{userId}/lockbox/{clientFileId}/1/container.fdcse
users/{userId}/lockbox/{clientFileId}/1/manifest.fdmanifest
users/{userId}/lockbox/{clientFileId}/1/signature.fdsig
```

Suggested content types:

```text
application/x-filedrive-csemlk03
application/x-filedrive-lockbox-manifest
application/x-filedrive-lockbox-signature
```

Never let client filenames become MinIO object keys.

If any upload or database operation fails, delete every object uploaded by that request. Always delete all staging files. Cleanup failures should be attached/surfaced without hiding the original failure. Remember that a database transaction cannot roll back MinIO, so explicit compensation is required.

Handle race conditions: the database uniqueness constraint is authoritative. If two requests race, only one may succeed, and the losing request must clean up only objects it owns. Prefer request-unique temporary object keys followed by a safe commit strategy if deterministic final keys could cause one request to delete another request's successful object.

## Service changes

Refactor the upload portion of `LockboxService` rather than damaging unrelated folder/list/download behavior. It is acceptable to extract a dedicated `LockboxV3UploadService` if that keeps responsibilities clearer.

The service flow must be:

```text
current authenticated user
-> enabled Lockbox profile
-> owned destination Lockbox folder
-> stage three parts
-> validate signature, manifest, hash, container, device and keys
-> reject duplicate
-> upload three objects
-> persist FileMetaData and LockboxFile
-> return logical file response
-> clean temporary resources
```

Use SHA3-512 for the container hash. Do not retain the legacy SHA-256 checksum as the authoritative CSEMLK03 integrity value. If `FileMetaData.checksum` is mandatory, store the lowercase hex SHA3-512 value and clearly document its algorithm, or leave it null if the model permits and use `LockboxFile.containerHash` as authoritative.

Do not run malware scanning or content inspection against ciphertext as though it were plaintext.

## Response contract

Change `LockboxUploadResponse` to return public logical metadata, for example:

```java
public record LockboxUploadResponse(
        Long id,
        UUID clientFileId,
        long revision,
        Long parentId,
        long containerSize,
        String containerHash,
        int formatVersion,
        int suiteId,
        Instant createdAt
) {}
```

Encode binary IDs/hashes consistently as lowercase hexadecimal in JSON. Do not return private/encrypted metadata bytes.

The client needs, at minimum, `id`, `clientFileId`, `revision`, and confirmation of the accepted container hash.

## Listing behavior

Update Lockbox file-list DTOs so they return opaque public information only:

- backend database ID
- client file UUID
- revision
- container size
- server creation time
- format version/suite

Do not pretend the opaque `.fdcse` filename is the user's original filename. The client will eventually download and decrypt metadata to display the private filename.

## Download behavior

The current single download endpoint is insufficient because v3 decryption requires all three exact artifacts.

Provide authenticated ownership-checked endpoints such as:

```http
GET /api/lockbox/files/{id}/container
GET /api/lockbox/files/{id}/manifest
GET /api/lockbox/files/{id}/signature
```

Each endpoint must stream exactly the stored bytes with `Cache-Control: no-store`, a safe opaque attachment filename, correct content length, and the corresponding content type. Do not parse and reserialize the manifest during download.

Keep or adapt the old `/download` endpoint only if required for legacy CSEMLK01/CSEMLK02 compatibility. Do not make a v3 record return only the container.

## Error handling

Return stable, client-actionable 4xx errors for malformed or unauthorized uploads rather than generic 500 responses. Introduce an exception/error-code approach consistent with the existing `ApiExceptionHandler`.

Useful error codes include:

```text
LOCKBOX_NOT_ENABLED
DEVICE_NOT_ACTIVE
UNKNOWN_SIGNING_KEY
UNKNOWN_ENCRYPTION_KEY
INVALID_MANIFEST
INVALID_SIGNATURE_RECORD
INVALID_SIGNATURE
CONTAINER_HASH_MISMATCH
CONTAINER_SIZE_MISMATCH
MANIFEST_CONTAINER_MISMATCH
UNSUPPORTED_LOCKBOX_VERSION
UNSUPPORTED_REVISION
DUPLICATE_LOCKBOX_FILE
ARTIFACT_TOO_LARGE
```

Do not reveal whether a key or file belongs to another user; return the same not-found/invalid response used for an unknown value.

## Tests required

Add focused unit tests for every binary parser and integration/service tests for upload behavior. Tests must cover at least:

### Success

- known-good CSEMLK03 container + manifest + signature uploads successfully
- all three stored objects are byte-for-byte identical to the submitted artifacts
- correct database fields are persisted
- response contains the signed UUID, revision, size, and hash
- authenticated download returns the exact three original byte sequences

### Tampering and mismatch

- one-byte manifest modification
- one-byte signature modification
- one-byte container modification
- truncated and trailing manifest
- truncated and trailing signature record
- truncated container/header/section
- wrong manifest magic/version/suite/hash algorithm
- wrong container magic/version/suite
- container size mismatch
- container hash mismatch
- client UUID mismatch
- revision mismatch
- signing key ID mismatch
- encryption key ID mismatch
- device UUID mismatch
- nonzero `previousManifestHash` at revision 1
- unknown, revoked, or wrong-user signing key/device
- unknown, revoked, or wrong-user encryption key
- disabled/suspended Lockbox profile
- duplicate upload and concurrent duplicate race
- oversized artifacts
- multipart filename/path tricks

### Cleanup

- second object upload fails after first succeeds
- third object upload fails after two succeed
- database persistence fails after all objects upload
- no temporary files or orphaned objects remain after each failure

Use permanent known-good test fixtures generated by the Rust v3 implementation where practical. Do not generate the expected Java parsing result using the same Java parser under test. Include exact boundary/offset assertions.

## Legacy compatibility

Do not change CSEMLK01 or CSEMLK02 byte semantics. If existing legacy download support is retained, keep it explicitly separate from the new v3 path. New uploads may be v3-only for this task.

Remove or retire only the obsolete v2 upload-specific pieces after the v3 replacements compile and tests pass:

- CSEMLK02-only `LockboxContainerValidator`
- old `LockboxContainerInfo`
- single-file multipart upload implementation
- legacy single-file upload response shape
- duplicated `LockboxFile.encryptedMetadata`

Do not delete enrollment classes, registered-key data, folder ownership logic, authentication services, or MinIO support.

## Completion requirements

Before reporting completion:

1. Run the full Maven test suite.
2. Run any database/container integration tests available in the repository.
3. Verify the application starts with the configured database and MinIO services.
4. Provide a concise summary of files kept, modified, added, and removed.
5. Provide the final exact upload request contract that the Java desktop client must implement, including multipart field names and response JSON.
6. Report any legacy migration or compatibility limitation explicitly.

Implement the backend completely; do not modify the desktop client in this task.
