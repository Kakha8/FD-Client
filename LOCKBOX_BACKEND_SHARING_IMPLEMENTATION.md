# Lockbox v3 Backend Sharing Implementation

## Objective

Complete Lockbox v3 sharing in the Spring backend at:

`C:\git-repos\File-Drive-Spring`

Sharing is immediate. There is no recipient accept/decline workflow. A successfully verified share becomes `ACTIVE` as soon as it is created. The owner may later revoke it.

The backend must never receive, store, unwrap, or decrypt a plaintext DEK or any private key. The sender client performs ML-KEM encapsulation, wraps the file DEK, constructs the canonical sharing transcript, and signs it with its ML-DSA-87 private key. The backend verifies and stores only the resulting public cryptographic artifacts.

## Required protocol source

Before changing code, read this entire document:

`C:\Users\Kakha\Downloads\CSEMLK03_CODEX_ARCHITECTURE.md`

Also inspect the client protocol implementation when necessary:

- `C:\git-repos\FD-Client\native-rust\src\csemlk03.rs`
- `C:\git-repos\FD-Client\native-rust\src\owner_envelope.rs`
- `C:\git-repos\FD-Client\native-rust\src\dek_envelope.rs`
- `C:\git-repos\FD-Client\native-rust\src\mldsa.rs`

Do not invent a transcript format or cryptographic representation. If the architecture document does not yet define the sharing-envelope transcript, stop and report the missing protocol definition instead of creating an incompatible format. Backend and Rust must encode exactly the same bytes.

## Existing backend foundation

Inspect the current source before editing. Relevant existing classes include:

- `model/LockboxShare.java`
- `model/LockboxShareEnvelope.java`
- `model/LockboxFile.java`
- `model/LockboxKey.java`
- `model/LockboxDevice.java`
- `repository/LockboxShareRepository.java`
- `repository/LockboxShareEnvelopeRepository.java`
- `repository/LockboxFileRepository.java`
- `repository/LockboxKeyRepository.java`
- `services/lockbox/LockboxSharingService.java`
- `controller/LockboxSharingController.java`
- `dto/lockbox/LockboxCreateShareRequest.java`
- `dto/lockbox/LockboxShareResponse.java`

The recipient-key lookup already works:

`GET /api/lockbox/share-recipients/{username}/keys`

Preserve that endpoint and its privacy behavior.

## 1. Simplify the share lifecycle

Change `LockboxShare` to use only:

```java
public enum Status {
    ACTIVE,
    REVOKED
}
```

Remove the pending/accept/decline lifecycle:

- Remove `PENDING` and `DECLINED`.
- Remove `accept()` and `decline()`.
- Remove `acceptedAt` and `declinedAt`.
- Add `activatedAt`, non-null and immutable after creation.
- A new share must start as `ACTIVE` and set `activatedAt`.
- Keep idempotent `revoke()` behavior and `revokedAt`.

Use an explicit database migration if this project has migrations. Do not rely on destructive schema recreation. Preserve existing data where possible. If Hibernate schema auto-update is currently used for development, still document the eventual migration requirement.

Remove or update repository methods referring to statuses that no longer exist. Also remove invalid derived-query methods using nonexistent property paths such as `recipientUserId`; the entity property is `recipient`, whose ID path is `recipientId`.

## 2. Use a complete create-share request

The request must contain all fields required by `LockboxShareEnvelope`, encoded with standard padded Base64 unless the architecture specifies otherwise:

```java
public record LockboxCreateShareRequest(
        Long fileId,
        String recipientUsername,
        String recipientKeyId,
        String ownerSigningKeyId,
        String kemCiphertext,
        String wrapNonce,
        String wrappedDek,
        String ownerSignature
) {
}
```

Do not use a client-provided `wrappingAlgorithm` string as authority. Algorithms are determined from the registered key records and the v3 suite.

Apply strict request limits before allocating or processing large data. For the current suite, reconcile constants with the architecture and Rust implementation. Expected values currently include:

- key ID: 32 bytes
- ML-KEM-1024 ciphertext: 1,568 bytes
- AES-GCM nonce: 12 bytes
- wrapped 32-byte DEK with GCM tag: 48 bytes
- ML-DSA-87 signature: 4,627 bytes

Reject malformed Base64 and incorrect lengths with a stable `400` Lockbox API error.

## 3. Canonical sharing transcript and verification

Implement a dedicated encoder, for example:

`services/lockbox/LockboxShareTranscript.java`

It must serialize the exact canonical bytes defined by the architecture and shared with the Rust client. It must bind at least every security-relevant value required by the protocol, including the identities/IDs of the file, owner, recipient, relevant keys, KEM ciphertext, nonce, wrapped DEK, permission, version/suite, and any anti-replay/domain-separation fields specified by the architecture.

Never sign ambiguous concatenated strings or JSON whose canonicalization is undefined.

Implement or extend a verifier using Bouncy Castle ML-DSA-87. Verify `ownerSignature` against the canonical transcript and the registered active owner signing public key before saving the share or envelope.

Requirements:

- Fail closed.
- Return a stable `400` error for an invalid signature.
- Do not persist either entity when verification fails.
- Do not log cryptographic payloads, tokens, plaintext metadata, or key material.
- Use constant-time/library verification; do not compare signatures manually.

## 4. Create-share service

Implement `LockboxSharingService.createShare(...)` transactionally.

It must:

1. Resolve the authenticated owner with `ResourceAccessService`.
2. Load `fileId` using `LockboxFileRepository.findByIdAndProfileUserId(fileId, ownerId)`.
3. Return `404` if the file is not owned by the caller, is deleted, or is permanently deleted. Do not reveal whether another user's file exists.
4. Resolve the recipient by normalized username.
5. Reject sharing with oneself.
6. Decode and validate all Base64 fields and exact lengths.
7. Load `recipientKeyId` and prove that it is:
   - owned by the recipient,
   - on an `ACTIVE` recipient device,
   - role `ENCRYPTION`,
   - algorithm `ML_KEM_1024`,
   - status `ACTIVE`.
8. Load `ownerSigningKeyId` and prove that it is:
   - owned by the authenticated owner,
   - on an `ACTIVE` owner device,
   - role `SIGNING`,
   - algorithm `ML_DSA_87`,
   - status `ACTIVE`.
9. Build the canonical transcript and verify the ML-DSA-87 signature.
10. Prevent an existing `ACTIVE` share for the same file and recipient. Return `409` for duplicates.
11. Create an immediately `ACTIVE`, read-only `LockboxShare`.
12. Create the corresponding `LockboxShareEnvelope`.
13. Save both in one transaction and return a safe response.

Do not trust usernames, permissions, algorithms, owner IDs, or statuses supplied by the client when the backend can derive them.

Handle the database unique constraint as a `409`, including races between concurrent duplicate requests.

## 5. Create-share endpoint

Expose:

```http
POST /api/lockbox/shares
Authorization: Bearer <access token>
Content-Type: application/json
```

Return `201 Created` with a DTO such as:

```java
public record LockboxShareResponse(
        String shareId,
        Long fileId,
        String ownerUsername,
        String recipientUsername,
        String recipientKeyId,
        String status
) {
}
```

The returned status must be `ACTIVE`.

Use a clean controller mapping. Do not accidentally place this endpoint under `/api/lockbox/share-recipients/shares` because the existing controller has a recipient-lookup base path; either adjust the controller structure carefully or create a dedicated `LockboxShareController` mapped to `/api/lockbox/shares`.

## 6. Received-share listing

Expose:

```http
GET /api/lockbox/shares/received
```

Return only shares where:

- authenticated user is the recipient,
- share status is `ACTIVE`,
- source file is not deleted or permanently deleted.

Return enough public metadata for the client to render the row and request the private encrypted metadata/artifacts. Do not expose object-store keys, internal entity IDs unnecessarily, or another recipient's envelope.

Avoid N+1 queries using an appropriate repository query/entity graph if needed.

## 7. Recipient envelope retrieval

Expose:

```http
GET /api/lockbox/shares/{shareId}/envelope
```

Only the authenticated recipient of an `ACTIVE` share may retrieve it. Return only that recipient's envelope:

- recipient key ID
- owner signing key ID
- KEM ciphertext
- wrap nonce
- wrapped DEK
- owner signature
- protocol/suite information required by the client

Encode binary fields consistently in Base64. Add `Cache-Control: no-store`.

## 8. Shared file metadata and download authorization

Update Lockbox metadata and download authorization so access is allowed when either:

- the authenticated user owns the file, or
- the authenticated user is the recipient of an `ACTIVE` share for the file.

The source file must still be non-deleted and non-permanently-deleted.

Do not weaken ownership checks globally. Add a centralized helper specifically for Lockbox owner-or-active-recipient authorization and use it consistently for:

- private metadata needed to decrypt the filename,
- manifest retrieval,
- signature retrieval,
- container download/header/range access.

A `REVOKED` share must immediately lose all metadata, envelope, and download access.

## 9. Revocation

Expose:

```http
DELETE /api/lockbox/shares/{shareId}
```

Only the source-file owner may revoke. Revocation should be idempotent. Keep the share and envelope rows for audit/history unless the architecture or retention policy requires otherwise. A revoked envelope must no longer be retrievable by the recipient.

If the source Lockbox file is deleted, every related share must become inaccessible even if its row still says `ACTIVE`. Optionally revoke active shares during deletion as defense in depth, but authorization must always check current file deletion state.

## 10. Error handling

Use stable Lockbox error codes and correct HTTP statuses, including:

- malformed request or invalid cryptographic field: `400`
- invalid envelope signature: `400`
- unauthenticated: `401`
- unauthorized/non-owned/non-shared resource: preferably non-enumerating `404`
- recipient/key unavailable: `404`
- duplicate active share: `409`
- unsupported HTTP method: `405`, not generic `500`

The global exception handler currently turns `HttpRequestMethodNotSupportedException` into `500`. Add appropriate handling so framework HTTP errors retain correct status codes without exposing stack traces.

## 11. Tests

Add service/integration tests covering at least:

- valid envelope creates one `ACTIVE` share and one envelope
- valid share returns `201`
- invalid ML-DSA signature persists nothing
- malformed Base64 and every incorrect binary length are rejected
- cannot share with self
- cannot share another user's file
- deleted/permanently deleted file cannot be shared
- recipient key must belong to recipient and be active ML-KEM-1024
- owner signing key must belong to caller and be active ML-DSA-87
- duplicate active share returns `409`, including database-constraint fallback
- recipient can list active received shares
- unrelated user cannot list/retrieve the share or envelope
- recipient can retrieve only its own envelope
- active recipient can retrieve private metadata and download artifacts
- revoked recipient cannot retrieve metadata, envelope, or download artifacts
- owner can revoke; recipient/unrelated user cannot revoke
- deleted source file is inaccessible through a share
- POST to the GET recipient-key endpoint returns `405`, not `500`

Use real ML-DSA test vectors or generate a real test keypair/signature with the same provider. Do not make the verifier mock return `true` in the principal integration test.

## 12. Verification and delivery

Run:

```powershell
mvn.cmd test
```

Then, if tests pass, rebuild the backend container:

```powershell
docker compose up -d --build app
```

Verify startup logs and smoke-test the endpoints. Do not modify the desktop client as part of this backend task.

At completion, report:

- files changed,
- final endpoint list,
- exact canonical transcript definition used,
- signature verification provider/algorithm,
- tests added and results,
- any required database migration,
- any remaining client-side work.

## Non-goals

Do not implement these in this task:

- accept/decline or pending-share workflow
- server-side DEK decryption
- server-side private keys
- plaintext filename or plaintext file processing
- public-link sharing
- multi-recipient bulk sharing
- resharing by recipients
- client UI changes

