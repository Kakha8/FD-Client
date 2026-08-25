# Backend task: account-scoped Lockbox installation handles

## Objective

Add an account-scoped installation handle to Lockbox device enrollment so the backend can distinguish separate client installations without receiving or storing the client's raw installation UUID.

This task is only for installation tracking. Do **not** implement self-sharing/device grants yet.

Backend repository:

```text
C:\git-repos\File-Drive-Spring
```

Protocol architecture document:

```text
C:\Users\Kakha\Downloads\CSEMLK03_CODEX_ARCHITECTURE.md
```

Read the architecture document completely before modifying protocol-sensitive code. Also inspect the current enrollment model, DTOs, controller, service, transcript encoder, repositories, exceptions, and tests. Preserve unrelated code and existing user changes.

## Security model

The client owns a randomly generated raw installation UUID stored locally at:

```text
%LOCALAPPDATA%\FileDrive\installation.json
```

The raw installation UUID is not secret, but it must never be sent to or stored by the backend.

The client sends a 32-byte account-scoped installation handle:

```text
SHA3-256(
    ASCII("FD-INSTALLATION-HANDLE-V1\0")
    || rawInstallationUuidBytes
    || userPublicUuidBytes
)
```

Encoding requirements:

- The domain is exact ASCII and includes the trailing NUL byte.
- UUIDs are the canonical 16 raw bytes in network/RFC 4122 order, not UUID strings.
- The output is exactly 32 bytes.
- Transport it as canonical Base64 in JSON.
- The backend does not recompute this value because it does not know the raw installation UUID.
- Treat it as an identifier/grouping hint, not authentication or proof of physical hardware.
- Proof of possession still comes from the enrollment challenge signed by the device ML-DSA-87 key.

## Data model

Add this field to `LockboxDevice`:

```java
@Column(
        name = "installation_handle",
        length = 32,
        updatable = false
)
private byte[] installationHandle;
```

For the current H2 development database, keep the field nullable temporarily so existing rows can load. Document that production migration should backfill/re-enroll existing devices and then enforce `nullable = false`.

Use defensive copying:

```java
public byte[] getInstallationHandle() {
    return installationHandle == null
            ? null
            : installationHandle.clone();
}
```

Update constructors/factory methods so new enrollments require exactly 32 bytes. Never retain a caller-owned mutable array.

Add a profile-scoped unique constraint to `lockbox_devices`:

```java
@UniqueConstraint(
        name = "uk_lockbox_device_profile_installation",
        columnNames = {
                "profile_id",
                "installation_handle"
        }
)
```

Do not make `installation_handle` globally unique. Different accounts on the same Windows installation deliberately derive different handles.

Preserve the existing unique device UUID constraint unless the repository design clearly requires a separate migration.

## Repository

Add an appropriate lookup such as:

```java
Optional<LockboxDevice> findByProfileIdAndInstallationHandle(
        Long profileId,
        byte[] installationHandle
);
```

Use this only for enrollment conflict/idempotency checks. Do not expose an endpoint that allows arbitrary users to query installation handles.

## Enrollment API changes

Find the current begin/complete enrollment flow and its DTOs. The installation handle must be supplied before the server challenge is signed so it can be bound into the signed transcript.

Preferred flow:

1. Client calls the existing enrollment-begin endpoint with:
   - account-specific `deviceUuid`
   - Base64 32-byte `installationHandle`
   - display name, if already part of begin enrollment
2. Backend validates and stores the hash of the challenge plus pending enrollment context, or returns the installation handle in the challenge response for exact client transcript construction.
3. Client signs the updated canonical enrollment transcript.
4. Client sends the complete-enrollment request containing the same device UUID and installation handle, public keys, and signature.
5. Backend rejects any mismatch between begin and complete context.
6. Backend creates `LockboxDevice` with the installation handle.

If the current begin endpoint has no request body and adding the context there would cause excessive restructuring, extend the pending `LockboxEnrollmentChallenge` model with the required enrollment context. Do not accept an installation handle only at completion without signing it.

## Canonical enrollment transcript

Update the existing Java enrollment transcript encoder and the architecture document so the exact 32 installation-handle bytes are included in the signed message.

Do not invent an unrelated second signature. Extend/version the existing enrollment transcript deliberately.

Recommended approach:

- Introduce a new enrollment transcript domain/version, for example:

```text
FD-CSE-V3-ENROLLMENT-V2\0
```

- Preserve the existing field order and fixed-width encodings, adding the installation handle at a precisely documented location.
- Write the complete byte-level field order, widths, endianness, and domain bytes into `CSEMLK03_CODEX_ARCHITECTURE.md`.
- The Java encoder must produce exactly the bytes described there.
- A corresponding client/Rust encoder will be implemented after this backend contract is finalized.

If the current protocol already has an explicit extension/version mechanism, use it instead. Do not silently append bytes to a transcript while keeping the same domain/version.

## Validation

At the HTTP boundary:

- Reject null or blank installation handles.
- Reject invalid Base64.
- Reject decoded values not exactly 32 bytes.
- Prefer canonical Base64: decoding and re-encoding should produce the submitted value.
- Do not log the raw handle, public keys, challenge, or signatures.
- Use the existing structured Lockbox API exception format.
- Return `400 Bad Request` for malformed handles.
- Return `409 Conflict` when the same profile already has an incompatible active enrollment for that installation handle.
- Avoid leaking another user's device information.

## Enrollment conflict behavior

For one profile/account:

- Same installation handle + same active device UUID/key identities: treat according to existing idempotency/retry semantics.
- Same installation handle + different active device UUID or different active key identities: return a conflict; do not silently replace the existing device.
- Different installation handle: allow another device enrollment.
- Same physical installation used by a different account: allow it because its account-scoped handle is different.
- Revoked device with the same installation handle: follow the existing re-enrollment policy explicitly; do not automatically reactivate a revoked key without a fresh challenge and signature.

Do not use the handle as authorization. All enrollment completion must still verify the challenge, expiry, single use, device UUID, public-key IDs, algorithms, and ML-DSA-87 signature.

## Response/device-management changes

If there is an authenticated device-list/status response, add only useful non-sensitive information:

- device UUID
- display name
- status
- created/activated/last-seen timestamps
- key IDs/fingerprints where already appropriate
- optionally a boolean or opaque shortened label indicating installation association

Do not return the full installation handle unless the desktop client has a concrete need for it. It is an internal correlation value.

## Database/H2 notes

The project currently uses H2 during development. Ensure Hibernate can start with existing rows where `installation_handle` is null.

Be aware that SQL unique constraints commonly allow multiple null values. That is acceptable only during the migration period. New enrollment service code must always provide a non-null 32-byte handle.

Do not delete existing Lockbox rows or reset the database to make the change pass.

## Tests required

Add or update tests covering at least:

1. A valid 32-byte installation handle completes enrollment and is persisted.
2. Invalid Base64 is rejected.
3. Decoded lengths of 0, 31, and 33 bytes are rejected.
4. The handle is included in the exact signed transcript.
5. Modifying one handle byte after signing causes signature verification to fail.
6. Begin/complete handle mismatch is rejected.
7. The same account cannot create conflicting active device enrollments for the same handle.
8. The same account can enroll a different installation handle.
9. Different accounts can enroll independently without a global uniqueness conflict.
10. Existing nullable rows do not prevent application startup during migration.
11. Repository/context tests verify the profile-scoped lookup.
12. Existing enrollment, sharing, received-share, upload, download, and application-context tests continue to pass.

Where possible, include a deterministic known transcript vector asserting exact bytes rather than testing only that signing succeeds.

## Completion requirements

Before reporting completion:

1. Run:

```powershell
mvn.cmd test
```

2. Report changed files and test counts.
3. Report the exact finalized enrollment transcript layout needed by the Rust client.
4. Clearly identify any temporary nullable migration behavior.
5. Do not implement the client or self-sharing/device grants in this backend task.

