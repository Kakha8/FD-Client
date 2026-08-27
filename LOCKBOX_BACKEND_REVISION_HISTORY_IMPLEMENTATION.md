# Lockbox Backend Revision History Implementation

## Objective

Add immutable revision history to the Spring backend while preserving Lockbox end-to-end encryption.

The backend must distinguish:

- A **logical Lockbox file**, identified by one stable `clientFileId`.
- Its **immutable encrypted revisions**, numbered `1, 2, 3, ...`.
- **Version-specific shares**. A share for revision 1 must remain on revision 1 when revision 2 is uploaded.

The latest revision is shown in the normal file listing. Older revisions are available through a revision-history endpoint.

Do not automatically copy shares to a new revision. A newly uploaded revision starts private. Existing shares continue to grant access only to their original revision.

## Existing protocol constraints

Do not invent a new cryptographic format. Continue using the existing CSEMLK03 manifest, signature, container, and sharing-envelope parsers and validators.

The existing manifest already contains:

- `clientFileId`
- `revision`
- `previousManifestHash`
- `containerHash`
- `containerSize`
- signing/encryption key IDs
- signing device UUID

The required chain is:

- Revision 1 has an all-zero `previousManifestHash`.
- Revision `N > 1` has `previousManifestHash = SHA3-512(exact manifest bytes of revision N - 1)`.
- Revisions must increase exactly by one. Never accept skipped or decreasing revisions.

The backend never receives or stores plaintext filenames, plaintext metadata, DEKs, private keys, or decrypted file contents.

## Development database assumption

The application currently uses H2 for development. It is acceptable to drop and recreate the Lockbox schema/data instead of writing a production migration.

Do not silently add a fragile partial migration. If Hibernate schema recreation is already configured for development, update the entities and recreate H2. If tests build an in-memory schema, ensure the updated entities create the correct constraints.

## Data model

### `LockboxFile`: logical file

Refactor the existing `LockboxFile` entity so it represents the logical file, not one physical encrypted revision.

It should retain:

- Existing shared primary key / relation to `FileMetaData`, if that remains compatible with the repository architecture.
- `profile`
- Stable `clientFileId`
- `currentRevision` (positive `long`)
- `createdAt`
- `updatedAt`

Revision-specific fields must move out of `LockboxFile`:

- revision number for a physical artifact set
- format version
- suite ID
- container size and hash
- encryption key ID
- signing key ID
- device UUID
- chunk size and count
- container, manifest, and signature object keys

Add behavior such as:

```java
public void advanceToRevision(long expectedCurrentRevision, long nextRevision) {
    if (currentRevision != expectedCurrentRevision) {
        throw new IllegalStateException("Revision conflict");
    }
    if (nextRevision != expectedCurrentRevision + 1) {
        throw new IllegalArgumentException("Revision must increase by one");
    }
    currentRevision = nextRevision;
}
```

Keep `clientFileId` immutable.

Recommended constraints:

```text
UNIQUE(profile_id, client_file_id)
current_revision >= 1
```

### New `LockboxFileRevision`: immutable encrypted revision

Create an entity/table containing:

```text
id
lockbox_file_id       FK -> lockbox_files
revision
format_version
suite_id
container_size
container_hash        64 bytes
encryption_key_id     32 bytes
signing_key_id        32 bytes
device_uuid
chunk_size
chunk_count
container_object_key
manifest_object_key
signature_object_key
created_at
```

Required constraints:

```text
UNIQUE(lockbox_file_id, revision)
UNIQUE(container_object_key)
UNIQUE(manifest_object_key)
UNIQUE(signature_object_key)
revision >= 1
```

All cryptographic and storage identity fields in a revision must be immutable after insertion.

Suggested relation:

```java
@ManyToOne(fetch = FetchType.LAZY, optional = false)
@JoinColumn(name = "lockbox_file_id", nullable = false, updatable = false)
private LockboxFile lockboxFile;
```

### Shares reference a revision

Change `LockboxShare` so it references `LockboxFileRevision`, not only the logical `LockboxFile`.

The logical file can be reached through:

```java
share.getRevision().getLockboxFile()
```

Every share and share envelope remains revision-specific. Do not mutate an existing share to point to a new revision.

Review and update:

- `LockboxShare`
- `LockboxShareEnvelope`
- sharing repository queries
- received-share queries
- share creation validation
- shared artifact download authorization
- response DTO construction

All existing checks comparing share-envelope context against `clientFileId`, `revision`, and `containerHash` must compare against the referenced `LockboxFileRevision`.

## Repositories

Add `LockboxFileRevisionRepository` with, at minimum:

```java
Optional<LockboxFileRevision> findByLockboxFileIdAndRevision(
        Long lockboxFileId,
        long revision
);

List<LockboxFileRevision> findAllByLockboxFileIdOrderByRevisionDesc(
        Long lockboxFileId
);

boolean existsByLockboxFileIdAndRevision(
        Long lockboxFileId,
        long revision
);
```

For owner-authorized reads, either use explicit owner/profile predicates in repository methods or load the logical file with the existing ownership helper before querying revisions. Never authorize solely from a revision ID supplied by the caller.

Update `LockboxFileRepository` so duplicate logical identity is checked by:

```text
profile + clientFileId
```

not by:

```text
profile + clientFileId + revision
```

## Initial upload behavior

Keep:

```http
POST /api/lockbox/files
Content-Type: multipart/form-data
```

Parts:

- `container`
- `manifest`
- `signature`
- optional `parentFolderId`

For a new logical file, require:

```text
manifest.revision == 1
manifest.previousManifestHash == 64 zero bytes
```

Continue all current validation:

- authenticated user has an enabled Lockbox profile
- signing key belongs to the profile
- signing device is active
- signature record key ID equals manifest signing key ID
- manifest signature is valid
- manifest device matches the signing-key device
- multipart filenames match the manifest `clientFileId`
- actual container size equals signed size
- actual SHA3-512 container hash equals signed hash
- container public fields match the manifest
- encryption key is known and valid
- format/suite/chunk constraints are valid

Then atomically create:

1. The `FileMetaData` row.
2. The logical `LockboxFile` with `currentRevision = 1`.
3. The immutable `LockboxFileRevision` for revision 1.
4. The three encrypted storage objects.

The existing upload response may continue returning:

```json
{
  "id": 42,
  "clientFileId": "...",
  "revision": 1,
  "parentId": null,
  "containerSize": 123,
  "containerHash": "...",
  "formatVersion": 3,
  "suiteId": 1,
  "createdAt": "..."
}
```

Here `id` is the logical Lockbox file / existing server file ID.

## Upload-next-revision endpoint

Implement:

```http
PUT /api/lockbox/files/{fileId}/revisions?expectedRevision={N}
Content-Type: multipart/form-data
Authorization: Bearer ...
```

Parts:

- `container`
- `manifest`
- `signature`

The client is already prepared to call this exact route.

### Required validation

1. Authenticate the user.
2. Load `fileId` and verify the current user owns the logical Lockbox file.
3. Lock the logical row for update, or use an optimistic `@Version` field / compare-and-set update.
4. Require:

```text
logicalFile.currentRevision == expectedRevision
manifest.clientFileId == logicalFile.clientFileId
manifest.revision == expectedRevision + 1
```

5. Load revision `expectedRevision`.
6. Read its exact stored manifest bytes with a strict size bound.
7. Compute:

```text
SHA3-512(previous exact manifest bytes)
```

8. Require constant-time equality with `manifest.previousManifestHash`.
9. Perform every signature, active-device, key, size, hash, container, filename, and format validation used by initial upload.
10. Reject if the `(logical file, next revision)` row already exists.

Use these responses:

- `200 OK` for a successful new revision.
- `400 Bad Request` for malformed/cryptographically inconsistent artifacts.
- `401/403` for authentication/ownership/device failures, consistent with existing API conventions.
- `404 Not Found` when the owned logical file does not exist.
- `409 Conflict` when `expectedRevision` is stale or the next revision already exists.

### Storage and transaction behavior

Use revision-specific, request-unique keys, for example:

```text
users/{userId}/lockbox/{clientFileId}/{revision}/requests/{requestUuid}/container.fdcse
users/{userId}/lockbox/{clientFileId}/{revision}/requests/{requestUuid}/manifest.fdmanifest
users/{userId}/lockbox/{clientFileId}/{revision}/requests/{requestUuid}/signature.fdsig
```

Do not overwrite or delete previous revision objects.

Required commit order:

1. Stage and validate multipart files in a temporary directory.
2. Upload the three new encrypted objects under new keys.
3. Register rollback cleanup for those newly uploaded keys.
4. Insert the immutable new revision row.
5. Advance `LockboxFile.currentRevision` using the expected revision guard.
6. Commit.
7. Never alter old revisions or their shares.

If any step fails, the logical current revision must remain unchanged and newly uploaded objects must be cleaned up.

Return the normal upload response with the logical file ID and new revision number.

## Revision-history endpoint

Implement:

```http
GET /api/lockbox/files/{fileId}/revisions
Authorization: Bearer ...
```

Only the owner may call this endpoint initially.

Suggested response:

```json
{
  "fileId": 42,
  "clientFileId": "c29e...",
  "currentRevision": 2,
  "revisions": [
    {
      "revision": 2,
      "containerSize": 429916160,
      "containerHash": "lowercase hex",
      "createdAt": "2026-08-27T10:00:00Z",
      "sharedWithCount": 0,
      "current": true
    },
    {
      "revision": 1,
      "containerSize": 416179814,
      "containerHash": "lowercase hex",
      "createdAt": "2026-08-20T10:00:00Z",
      "sharedWithCount": 2,
      "current": false
    }
  ]
}
```

Do not return plaintext filename or decrypted metadata. The desktop client already knows the latest decrypted filename and can label the history dialog.

`sharedWithCount` counts active, non-expired shares for that specific revision. If implementing that count makes the first change unnecessarily complex, it may initially be omitted, but do not return an incorrect logical-file-wide count.

## Owner revision artifact downloads

Implement owner-authorized endpoints:

```http
GET /api/lockbox/files/{fileId}/revisions/{revision}/container
GET /api/lockbox/files/{fileId}/revisions/{revision}/manifest
GET /api/lockbox/files/{fileId}/revisions/{revision}/signature
```

Requirements:

- Verify ownership through the logical file.
- Load exactly the requested revision.
- Stream from that revision's object keys.
- Preserve `Content-Length`, no-store cache headers, content type, and safe content disposition.
- Keep the current async-security and async-timeout configuration used by existing streaming downloads.

The existing current-file download endpoints may remain as aliases that resolve `LockboxFile.currentRevision`:

```http
GET /api/lockbox/files/{fileId}/container
GET /api/lockbox/files/{fileId}/manifest
GET /api/lockbox/files/{fileId}/signature
```

This preserves compatibility with the current desktop client.

## Private metadata listing

`GET /api/lockbox/files/private-metadata` must return only each logical file's current revision.

For every logical file:

1. Load `currentRevision`.
2. Read the current revision's manifest, signature, and encrypted header.
3. Return the existing private-metadata DTO using the logical file ID, stable `clientFileId`, and current revision number.

Do not return every historical revision in the normal listing.

## Sharing changes

### Creating a share

Extend the create-share request to identify the selected revision explicitly:

```json
{
  "fileId": 42,
  "revision": 1,
  "shareUuid": "...",
  "recipientPublicUuid": "...",
  "recipientKeyId": "...",
  "recipientEnvelope": "...",
  "permission": "READ",
  "expiresAt": null,
  "targetDeviceId": "..."
}
```

If backward compatibility is required, a missing revision may temporarily mean the logical file's current revision. Prefer making it required once the client is updated.

Validate the recipient envelope against the chosen revision's:

- `clientFileId`
- revision number
- container hash
- recipient identity
- recipient key ID
- target device

Store the share against that immutable revision.

### Received shares

Received-share listing and individual-share responses must continue returning the revision referenced by the share.

If revision 1 was shared and the owner uploads private revision 2:

- The recipient still sees and downloads revision 1.
- The recipient is not told that private revision 2 exists.
- The share is not revoked or moved.

All received-share artifact endpoints must stream objects from the share's referenced revision.

### Sharing a later revision

When the owner explicitly shares revision 2, create a new revision-2 share/envelope. Do not rewrite the old revision-1 share.

Duplicate-share constraints should be revision-specific, for example:

```text
revision + target device
```

rather than logical file + target device across all history.

## Restore semantics

Do not implement “restore old revision” by decrementing `currentRevision`; that would violate the append-only chain.

When restore is added later, the client should download/decrypt the chosen historical revision and upload its contents as a brand-new next revision. Example:

```text
current revision 3
restore contents of revision 1
result is revision 4, chained from revision 3
```

Restore is not required for the initial backend implementation unless explicitly requested.

## Deletion semantics

For the initial implementation:

- Deleting the logical Lockbox file may delete all its revisions and shares using the existing permanent-delete behavior, after resolving exact object keys.
- Do not add individual revision deletion yet.
- Never delete or overwrite the previous revision during a new revision upload.

If logical deletion is destructive, preserve the existing confirmation/API behavior. Ensure storage cleanup covers all revision object keys and share/envelope rows.

## DTOs to add or update

Suggested new DTOs:

- `LockboxRevisionHistoryResponse`
- `LockboxRevisionItemResponse`

Update existing DTOs where needed:

- Upload response remains compatible.
- Share creation request/response includes revision.
- Received-share response already carries revision; ensure it comes from the referenced revision entity.
- Private metadata response continues representing only the current revision.

## Concurrency

Two devices may both read current revision 1 and attempt revision 2.

Exactly one must succeed. The other must receive `409 Conflict`.

Use one of:

- `@Version` optimistic locking on `LockboxFile` plus explicit conflict mapping.
- A repository method with `PESSIMISTIC_WRITE` for the owned logical file.
- An atomic conditional update such as `WHERE current_revision = :expectedRevision` and require one updated row.

Do not rely only on a pre-insert Java comparison because concurrent transactions can both pass it.

The unique `(lockbox_file_id, revision)` constraint is mandatory as a final database guard.

## Tests

Add focused tests covering at least:

### Initial upload

- Revision 1 with zero previous hash succeeds.
- Revision 1 creates one logical row and one revision row.
- New logical upload with revision greater than 1 is rejected.
- Revision 1 with a nonzero previous hash is rejected.

### New revision

- Revision 2 with the same `clientFileId` succeeds.
- Revision 2 becomes current.
- Revision 1 row and all three object keys remain unchanged.
- Revision 1 shares remain active and still reference revision 1.
- Revision 2 starts with zero shares.
- Wrong `clientFileId` is rejected.
- Skipped revision is rejected.
- Repeated/decreasing revision is rejected.
- Wrong `previousManifestHash` is rejected.
- Stale `expectedRevision` returns 409.
- Concurrent attempts produce one success and one conflict.
- Invalid signature/device/key/container/hash validation remains enforced.
- Failed database commit removes only newly uploaded objects.

### Listing and history

- Normal metadata listing returns only the current revision.
- History returns all revisions newest first.
- Another user cannot list or download the owner's revision history.
- Current download aliases resolve the latest revision.
- Historical download endpoints return the selected revision.

### Sharing

- A revision-1 share remains downloadable after revision 2 is uploaded.
- A revision-1 recipient cannot access revision 2.
- Explicitly sharing revision 2 creates an independent share/envelope.
- Envelope context must match the selected revision and container hash.
- Received-share listing does not reveal unshared newer revisions.

### Deletion

- Logical-file deletion cleans all revision objects and dependent shares according to current deletion rules.
- New-revision upload never deletes previous revision objects.

Run the full Maven test suite and report the exact result.

## Acceptance criteria

The implementation is complete only when:

1. A logical file can contain multiple immutable revisions.
2. Revision numbers are contiguous and manifest-hash chained.
3. New-revision upload uses optimistic concurrency and returns 409 on stale state.
4. The normal listing returns only the current revision.
5. The owner can list and download historical revisions.
6. Old revision objects are retained.
7. Existing shares remain attached to their original revisions.
8. New revisions start private.
9. Recipients cannot discover or download unshared newer revisions.
10. All cryptographic validation remains fail-closed.
11. Storage cleanup is transaction-safe.
12. All backend tests pass.

## Out of scope for this change

- Automatically carrying shares to new revisions.
- Reusing one DEK or file master key across revisions.
- Deleting individual historical revisions.
- Restoring by changing the current pointer backward.
- Browser-side decryption.
- Production SQL migration from existing schemas, because H2 development reset is currently acceptable.

