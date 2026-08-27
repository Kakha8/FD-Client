# Lockbox Backend Revision History — Remaining Fixes

## Goal

Finish and harden the existing Lockbox revision-history backend implementation.

The broad architecture is already correct:

- `LockboxFile` represents a logical file.
- `LockboxFileRevision` stores immutable encrypted revisions.
- Shares reference a specific revision.
- Revision upload, history, and historical download endpoints exist.
- Normal private-metadata listing resolves only the current revision.
- Old shares remain attached to old revisions.
- New revisions start private.

Do not redesign those parts. Make the targeted fixes below and add the missing tests.

The current Maven suite reports:

```text
Tests run: 59, Failures: 0, Errors: 0, Skipped: 0
BUILD SUCCESS
```

Passing existing tests is not sufficient because the important revision-upload and rollback cases are not covered.

## 1. Reject revision uploads when Lockbox is not enabled

### Current problem

`LockboxService.uploadRevision(...)` loads the logical file and its profile, but it does not explicitly require:

```java
profile.getStatus() == LockboxProfile.Status.ENABLED
```

The method later checks active signing/encryption keys, but an account with a suspended Lockbox profile may still have active keys. Revision upload must apply the same account-level policy as initial upload.

### Required change

After loading and owner-authorizing the logical file, require its profile to be enabled before staging multipart data or accessing object storage.

Use the same response semantics as initial Lockbox upload:

```java
LockboxProfile profile = logical.getProfile();

if (profile.getStatus() != LockboxProfile.Status.ENABLED) {
    throw new LockboxApiException(
            "LOCKBOX_NOT_ENABLED",
            HttpStatus.FORBIDDEN,
            "Lockbox is not enabled."
    );
}
```

Do not rely only on active device/key checks.

### Required tests

- Enabled profile can upload the next valid revision.
- Suspended profile receives `403` / `LOCKBOX_NOT_ENABLED`.
- Suspended profile is rejected before any object-storage upload.
- Active keys on a suspended profile do not bypass the profile check.

## 2. Make logical-file deletion storage-safe

### Current problem

`LockboxService.deleteLockboxFile(...)` currently loops through all revisions and immediately calls:

```java
storage.delete(...)
```

before the database transaction has committed its tombstone state.

This can create inconsistent states:

- The second or third object deletion fails after earlier objects were already removed.
- A database flush or commit fails after storage objects were removed.
- The database transaction rolls back, but deleted objects cannot be restored.
- Some historical revisions may retain only a subset of their artifacts.

### Required behavior

Do not delete revision objects before the database transaction successfully commits.

Implement commit-after cleanup:

1. Owner-authorize the logical file.
2. Load every immutable revision.
3. Collect exact container, manifest, and signature object keys into an immutable list.
4. Mark the `FileMetaData` row deleted/permanently deleted.
5. Save and flush the database state.
6. Register a transaction synchronization.
7. Delete collected storage keys only in `afterCommit()`.

Example structure:

```java
List<String> objectKeys = revisions
        .findAllByLockboxFileIdOrderByRevisionDesc(lockboxFile.getId())
        .stream()
        .flatMap(revision -> Stream.of(
                revision.getContainerObjectKey(),
                revision.getManifestObjectKey(),
                revision.getSignatureObjectKey()
        ))
        .toList();

// Set and flush database tombstone state first.
files.saveAndFlush(metadata);

TransactionSynchronizationManager.registerSynchronization(
        new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                deleteCommittedObjects(objectKeys);
            }
        }
);
```

### Cleanup failure policy

An object-store failure after commit cannot roll back the database. Handle it explicitly:

- Attempt all collected keys even if one deletion fails.
- Log every failed key without logging secrets or credentials.
- Prefer recording/scheduling cleanup for retry if the project already has a cleanup-job mechanism.
- At minimum, retain clear error logs so orphaned encrypted objects can be removed later.
- Keep deletion idempotent: a missing object should be treated as already deleted where supported.

Do not delete database revision rows merely to hide storage cleanup failures. The current tombstone approach is acceptable.

### Authorization after deletion

Ensure every owner revision endpoint treats a tombstoned logical file consistently:

```text
GET revision history
GET historical container
GET historical manifest
GET historical signature
GET current container/manifest/signature
```

After permanent deletion, these endpoints should return `404` rather than opening objects referenced by retained tombstone rows.

In particular, review `openRevisionDownload(...)`: it owner-authorizes the logical row but must also reject:

```java
file.getFile().isDeleted()
file.getFile().isPermanentlyDeleted()
```

Apply the same rule to current download aliases if they do not already enforce it.

### Required tests

- Successful logical deletion collects objects for every revision.
- Database tombstone is flushed before storage deletion begins.
- Transaction rollback causes zero storage deletions.
- Database commit causes all revision artifact keys to be attempted.
- One failed object deletion does not stop attempts for remaining keys.
- Repeating deletion is idempotent.
- Deleted logical files cannot use current or historical download endpoints.
- Deleted logical files cannot list revision history.

## 3. Add revision workflow tests

Add focused service and/or integration tests. Mock-only entity tests are not enough.

### Test fixture requirements

Create helpers that generate or load internally consistent test artifacts:

- Exact CSEMLK03 manifest bytes.
- Matching signature record and verifier behavior.
- Matching container public fields.
- Matching container size and SHA3-512 hash.
- Revision 1 with zero `previousManifestHash`.
- Revision 2 with `previousManifestHash = SHA3-512(exact revision-1 manifest bytes)`.

Tests may mock the cryptographic verifier and container parser when the test is about transaction orchestration, but the manifest identity, revision sequence, hash chaining, repository state, and object keys must still be asserted.

### Initial revision tests

- Initial upload creates one logical `LockboxFile`.
- Initial upload creates one `LockboxFileRevision` numbered 1.
- Logical `currentRevision` becomes 1.
- Revision 1 requires an all-zero previous-manifest hash.
- A new logical upload with revision 2 is rejected.
- Duplicate logical identity is rejected or follows the existing tombstone restoration policy safely.

### Successful next-revision test

Given logical file revision 1:

1. Upload a valid revision 2 with the same `clientFileId`.
2. Pass `expectedRevision=1`.
3. Use the exact SHA3-512 hash of revision 1's manifest.

Assert:

- Response is `200`.
- Logical file ID is unchanged.
- Stable `clientFileId` is unchanged.
- Logical `currentRevision` becomes 2.
- Revision 1 row remains unchanged.
- Revision 1 object keys remain unchanged.
- Revision 2 has three new, revision-specific, request-unique object keys.
- Revision 2 starts without shares.
- Existing revision-1 shares remain active and still reference revision 1.
- `FileMetaData` size/checksum/object key point to the current revision as intended.

### Invalid chain tests

Reject each of the following without advancing `currentRevision`:

- Wrong `clientFileId`.
- Repeated revision number.
- Decreasing revision number.
- Skipped revision number.
- All-zero previous hash for revision 2.
- Hash of container instead of previous manifest.
- Hash of parsed/re-encoded manifest instead of exact stored manifest bytes.
- Incorrect previous-manifest hash.
- Missing previous revision row.
- Duplicate `(logical file, revision)`.

No rejected request may leave a committed revision row.

### Optimistic/concurrent update tests

The repository already uses a pessimistic write lock and the logical entity has `@Version`. Verify actual behavior:

- Two requests both start with `expectedRevision=1`.
- Exactly one creates revision 2 and succeeds.
- The other receives `409 LOCKBOX_REVISION_CONFLICT`.
- There is exactly one revision-2 row.
- The logical current revision is exactly 2.
- No duplicate committed artifact set remains in storage.

If a deterministic true-concurrency integration test is too fragile for the default suite, add:

- A repository lock/transaction integration test.
- A service test proving stale `expectedRevision` returns 409.
- A unique-constraint test as the final database guard.

### Cryptographic validation regression tests

Revision upload must retain all initial-upload validation. Test rejection for:

- Unknown signing key.
- Signing key from another profile.
- Inactive/revoked signing device.
- Manifest device UUID mismatch.
- Signature-record key ID mismatch.
- Invalid manifest signature.
- Unknown encryption key.
- Container/manifest `clientFileId` mismatch.
- Container/manifest encryption-key mismatch.
- Container suite mismatch.
- Container size mismatch.
- Container hash mismatch.
- Invalid multipart artifact filenames.
- Suspended Lockbox profile.

### Rollback cleanup tests for revision upload

- Storage failure during container upload leaves no revision row.
- Storage failure during manifest upload cleans the uploaded container.
- Storage failure during signature upload cleans the uploaded container and manifest.
- Revision-row database failure cleans all three newly uploaded objects.
- Logical-file update failure cleans all three newly uploaded objects.
- A failed revision upload never deletes revision-1 objects.

### History and current listing tests

- Normal private metadata lists one item per logical file.
- Normal private metadata returns only the current revision artifacts.
- History returns all revisions newest first.
- History marks exactly one revision as current.
- Owner can list history.
- Another user receives `404` or the project's consistent authorization response.
- Tombstoned files cannot list history.

### Historical download tests

- Owner can download each revision's container, manifest, and signature.
- Current aliases resolve the current revision.
- Historical routes resolve exactly the requested revision.
- Unknown revision returns `404`.
- Another user cannot download an owner's revision.
- Tombstoned logical files cannot download any revision.
- Returned size/content type/name correspond to the selected revision.

### Version-specific sharing tests

- A revision-1 share remains active after private revision 2 upload.
- Received-share listing still reports revision 1.
- Received-share artifact download streams revision-1 object keys.
- Recipient cannot access unshared revision 2.
- Explicit revision-2 sharing creates an independent revision-2 share.
- Duplicate constraints are revision + target device, not logical file + target device.
- Share envelope context must match the selected revision number and container hash.
- Received-share APIs do not reveal the existence of an unshared newer revision.

## 4. Improve streaming performance for historical downloads

### Current issue

The controller uses:

```java
input.transferTo(outputStream);
```

The project previously experienced very slow large Lockbox downloads with this approach.

### Required change

Use the same explicit buffered streaming implementation for both current and historical Lockbox downloads.

Example:

```java
private static final int STREAM_BUFFER_SIZE = 1024 * 1024;

StreamingResponseBody body = output -> {
    try (InputStream input = result.inputStream()) {
        byte[] buffer = new byte[STREAM_BUFFER_SIZE];
        int read;
        while ((read = input.read(buffer)) != -1) {
            output.write(buffer, 0, read);
        }
        output.flush();
    }
};
```

Avoid duplicating the streaming code across current and historical controller methods. Both should call one helper.

Preserve:

- `Content-Length`
- correct artifact content type
- `Cache-Control: no-store`
- safe `Content-Disposition`
- the existing async dispatcher security allowance
- the configured long async request timeout

### Required tests

- Current and historical endpoints use the same response-building path.
- Streaming returns exact bytes.
- Stream and input are closed after success.
- Input is closed after write failure/client disconnect.
- Correct length and headers are returned.

## 5. Keep the API contract compatible with the client

The desktop client is prepared to call:

```http
PUT /api/lockbox/files/{fileId}/revisions?expectedRevision={currentRevision}
```

with multipart parts:

```text
container
manifest
signature
```

Keep that route unchanged.

The successful response must continue matching `LockboxUploadResponse`:

```json
{
  "id": 42,
  "clientFileId": "...",
  "revision": 2,
  "parentId": null,
  "containerSize": 123,
  "containerHash": "lowercase hex",
  "formatVersion": 3,
  "suiteId": 1,
  "createdAt": "..."
}
```

Stale state must return HTTP 409 so the client can display:

```text
This file changed on another device. Refresh and try again.
```

Do not expose plaintext metadata in revision-history responses.

## Acceptance criteria

The remaining backend work is complete only when:

1. Suspended Lockbox profiles cannot upload revisions.
2. Logical deletion never deletes storage objects before database commit.
3. Failed deletion cannot leave a rolled-back database row with prematurely removed objects.
4. Deleted logical files cannot access current or historical artifacts.
5. Valid revision 2 upload is tested end to end at the service/repository boundary.
6. Exact previous-manifest hash chaining is tested.
7. Stale and concurrent uploads are tested and return 409.
8. Revision-upload rollback cleanup is tested.
9. Revision-1 shares remain valid after private revision-2 upload.
10. Unshared newer revisions remain undiscoverable to recipients.
11. Current and historical downloads use the improved buffered streaming path.
12. The complete Maven test suite passes with zero failures and errors.

At completion, report:

- Files changed.
- New/updated endpoints.
- Tests added.
- Exact Maven test count and result.
- Any intentionally deferred cleanup-retry mechanism.

