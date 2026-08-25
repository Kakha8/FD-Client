# Lockbox Backend: Device-Targeted Self-Sharing Implementation

## Objective

Modify `File-Drive-Spring` so an authenticated Lockbox user can grant one of
their files to another active Lockbox device owned by the same account.

The implementation must continue supporting ordinary user-to-user sharing.
Self-sharing means **different devices under the same user**, not granting a
file back to the same device that signs the share.

Read the repository's protocol and architecture documents completely before
editing code, particularly:

- `CSEMLK03_CODEX_ARCHITECTURE.md`, wherever it is supplied;
- `LOCKBOX_SHARING_PROTOCOL.md`;
- existing Lockbox share-envelope parser, verifier, models, migrations and
  tests.

Do not invent or alter cryptographic byte formats. The existing share package,
signature message, domain separation, envelope framing and key algorithms stay
unchanged. A self-share uses the existing envelope context with:

- `ownerPublicUuid == recipientPublicUuid`;
- `recipientKeyId` equal to the selected target device's active ML-KEM-1024
  encryption key ID.

## Current blockers that must be removed correctly

The current `LockboxSharingService` rejects self-sharing in both
`recipientEncryptionKeys(...)` and `createShare(...)`.

It also detects duplicate shares by file and recipient **user**, while a
self-share must distinguish recipient devices.

Received-share listing, detail and download are currently scoped only to the
recipient user. They must additionally select the device targeted by the
stored recipient encryption key.

Do not merely delete the two self-sharing checks. That would leave incorrect
duplicate handling and would expose envelopes intended for one device in the
received-share responses of every device owned by the account.

## Security boundary

- Never expose raw installation UUIDs or `installation_handle` values.
- Device APIs may expose only the device's public UUID, display name, status
  and public encryption-key information.
- A device is owned by a user through
  `LockboxDevice -> LockboxProfile -> User`.
- Only `ACTIVE` devices and `ACTIVE` `ENCRYPTION` keys using `ML_KEM_1024` are
  eligible targets.
- The owner signing key must remain an `ACTIVE` `SIGNING` key using
  `ML_DSA_87`, owned by the authenticated owner.
- For a self-share, the recipient key's device must differ from the owner
  signing key's device. The signing key cryptographically identifies the
  source device more reliably than a client-supplied source-device UUID.
- A caller-provided device UUID is still only a selector under ordinary account
  JWT authentication; it is not independent device authentication. Do not
  claim otherwise. Envelope confidentiality remains protected by ML-KEM. A
  future device-bound token or signed request can strengthen this boundary.

## 1. Device/key response DTOs

Create DTOs under the existing Lockbox DTO package. Use project naming and
formatting conventions.

Suggested records:

```java
public record LockboxOwnDeviceKeyResponse(
        String keyId,
        String algorithm,
        String publicKey
) {}
```

```java
public record LockboxOwnDeviceResponse(
        UUID deviceId,
        String deviceName,
        String deviceStatus,
        List<LockboxOwnDeviceKeyResponse> encryptionKeys
) {}
```

```java
public record LockboxOwnDevicesResponse(
        List<LockboxOwnDeviceResponse> devices
) {
    public LockboxOwnDevicesResponse {
        devices = devices == null ? List.of() : List.copyOf(devices);
    }
}
```

Public keys and key IDs must use canonical padded Base64.

Do not include database IDs, installation handles, raw installation UUIDs,
private keys or signing private material.

## 2. Repository queries

Add explicit repository support for:

1. Listing the authenticated profile's active devices in stable order.
2. Loading active ML-KEM encryption keys for those devices.
3. Resolving a device by public device UUID and authenticated user ID.
4. Finding received shares whose envelope recipient key belongs to a specified
   active device owned by the authenticated user.
5. Finding an individual received share using all of:
   - share UUID;
   - recipient user ID;
   - target device UUID;
   - share status and expiry;
   - active target device/key state.
6. Detecting an existing share for the same Lockbox file and target device.

Prefer explicit `@Query` JPQL for multi-hop security queries instead of very
long derived method names. Fetch only what the service needs and avoid N+1
queries.

All received-share queries must join:

```text
LockboxShare
  -> LockboxShareEnvelope
  -> recipientKey
  -> device
  -> profile
  -> user
```

The joined device UUID must equal the requested `deviceId`, and the joined user
must equal the authenticated user.

## 3. Persist the target device on the share

Make device targeting explicit on `LockboxShare` rather than inferring the
security target only after loading the envelope.

Add an immutable `targetDevice` association:

```java
@ManyToOne(fetch = FetchType.LAZY, optional = false)
@JoinColumn(
        name = "target_device_id",
        nullable = false,
        updatable = false,
        foreignKey = @ForeignKey(name = "fk_lockbox_share_target_device")
)
private LockboxDevice targetDevice;
```

Update the constructor and every test fixture/call site.

Add indexes suitable for:

```text
target_device_id, status
recipient_user_id, target_device_id, status
```

For this H2 development phase, add a uniqueness constraint on:

```text
lockbox_file_id, target_device_id
```

This establishes at most one share row per file/device. If a revoked share is
shared again later, deliberately reactivate/update the existing share or add a
separate versioning design; do not silently create ambiguous duplicate rows.
Document the chosen lifecycle and test it.

Create the appropriate H2/manual migration. Do not rely solely on Hibernate
schema mutation. Existing share rows require a deterministic backfill from
their envelope recipient key's device before making the column non-null. If a
single SQL migration cannot safely backfill due the current schema/data, use a
two-phase migration and document it.

## 4. Authenticated own-device endpoint

Add:

```http
GET /api/lockbox/devices
Authorization: Bearer <access-token>
```

Optional query parameter:

```text
excludeDeviceId=<UUID>
```

Return all other active devices belonging to the authenticated user's Lockbox
profile, including their active ML-KEM encryption keys.

Requirements:

- return `200` with an empty list when no target device exists;
- `Cache-Control: no-store`;
- reject malformed UUIDs with the project's stable `400` error format;
- do not allow lookup of another user's devices;
- do not return revoked/pending devices or revoked/non-encryption keys;
- stable ordering by device creation time or public UUID, then key creation time
  or key ID.

This endpoint is distinct from username-based recipient discovery. Preserve
the existing user-to-user endpoint.

## 5. Recipient-key lookup behavior

Preserve:

```http
GET /api/lockbox/share-recipients/{username}/keys
```

for ordinary user-to-user sharing.

It may continue rejecting the requester's own username because self-sharing
now uses `/api/lockbox/devices`. This avoids ambiguous selection and preserves
the current external behavior.

## 6. `createShare(...)` validation

Keep all existing file ownership, deletion, envelope parsing, context binding,
algorithm, key-status, expiry and ML-DSA signature checks.

After resolving `recipient` and `recipientKey`, derive:

```java
LockboxDevice targetDevice = recipientKey.getDevice();
```

Validate the complete ownership chain and active states.

Ordinary share:

```text
recipient user != owner user
```

Continue accepting it as before.

Self-share:

```text
recipient user == owner user
```

Accept it only when:

- `context.ownerPublicUuid()` and `context.recipientPublicUuid()` both equal the
  authenticated owner's public UUID;
- the recipient key belongs to the authenticated owner's profile;
- the recipient key's device is active;
- the recipient key is active `ML_KEM_1024` with role `ENCRYPTION`;
- the owner signing key belongs to a different device from the target device;
- the owner signing key is active `ML_DSA_87` with role `SIGNING`;
- the share envelope signature verifies exactly as it does today.

Reject attempts to target the same device that signed the share with stable
`400` code and message, for example:

```text
LOCKBOX_SELF_SHARE_SAME_DEVICE
Select another registered device.
```

Do not accept a client-provided target device that disagrees with
`recipientKey.getDevice()`.

Store `targetDevice` on `LockboxShare` and store the same recipient key in
`LockboxShareEnvelope`. Before returning a response, ensure both associations
agree.

Duplicate detection must use file plus target device, not file plus recipient
user. Return a stable `409` for an already-active grant to that device.

## 7. Device-scoped received-share endpoints

Change the Lockbox received-share APIs to require a device UUID selector:

```http
GET /api/lockbox/shares/received?deviceId=<UUID>
GET /api/lockbox/shares/received/{shareUuid}?deviceId=<UUID>
GET /api/lockbox/shares/received/{shareUuid}/container?deviceId=<UUID>
```

Apply the same device selector to every other endpoint that returns a recipient
envelope or downloadable artifact.

For each endpoint:

- load the authenticated user;
- require an `ACTIVE` device with that UUID under the user's profile;
- require `share.recipient == authenticated user`;
- require `share.targetDevice == selected device`;
- require `envelope.recipientKey.device == selected device`;
- require the envelope recipient key ID to match the signed envelope context;
- preserve current active/expiry/deleted-file checks;
- return the normal not-found/unavailable response rather than revealing
  whether another device owns the share.

Do not return self-shares targeted to Device B when Device A is selected.
Ordinary user-to-user shares are also key/device-targeted and should follow the
same filtering rule.

## 8. Response behavior

The existing received-share response can remain compatible, but it may add:

```java
UUID targetDeviceId,
String targetDeviceName,
boolean selfShare
```

if useful to clients.

If fields are added, update all controller/service tests and document the JSON.
Do not expose installation handles.

`selfShare` must be derived server-side:

```java
share.getOwner().getId().equals(share.getRecipient().getId())
```

## 9. Controller and cache behavior

Add the own-device controller endpoint and update received endpoints with
required `deviceId` parameters.

Continue returning:

```http
Cache-Control: no-store
```

for device keys, envelopes and private metadata.

Use the existing `LockboxApiException` and global error response conventions.
Do not leak whether a foreign device/share/key exists.

## 10. Required tests

Add unit, controller and H2 integration tests covering at least:

### Own-device listing

- lists two active devices belonging to the current user;
- excludes the supplied current device UUID;
- excludes revoked and pending devices;
- excludes revoked, signing and wrong-algorithm keys;
- never returns installation handles;
- cannot list another user's devices;
- returns `Cache-Control: no-store`.

### Self-share creation

- Device A signing key can create an envelope for Device B encryption key under
  the same user;
- owner and recipient public UUIDs may be equal for this case;
- Device A cannot target Device A;
- a key belonging to another profile cannot be substituted;
- revoked target device/key is rejected;
- tampered envelope, key ID, signature, file UUID, revision and container hash
  remain rejected;
- a second share for the same file and Device B returns stable `409`;
- the same file can be granted separately to Device B and Device C;
- ordinary user-to-user sharing still passes.

### Device-scoped retrieval

- Device B lists and downloads its self-share;
- selecting Device A does not return Device B's share;
- selecting Device C does not return Device B's share;
- a foreign user cannot select Device B;
- revoked Device B can no longer list/detail/download the share;
- expired/revoked shares remain unavailable;
- envelope target device, stored share target device and selected device must
  all agree;
- ordinary recipient shares remain retrievable only through the device whose
  key was used.

### Persistence/migration

- `target_device_id` is populated and enforced;
- file/device uniqueness is enforced under concurrent or duplicate creation;
- existing share backfill is verified if migration fixtures exist.

## 11. Compatibility and client handoff

Document the final JSON contracts and endpoint paths in a short backend handoff
file for the desktop client.

The client will subsequently:

1. call `GET /api/lockbox/devices?excludeDeviceId=<currentDeviceId>`;
2. display device names/UUIDs;
3. select the target device's active ML-KEM key;
4. create the existing canonical share envelope locally;
5. sign it with the current device's ML-DSA key;
6. submit the existing create-share request;
7. pass its own device UUID to received listing/detail/download endpoints.

Do not implement browser-side private-key operations in the backend task.

## 12. Verification

Run the full backend suite:

```powershell
mvn.cmd test
```

or:

```powershell
.\mvnw.cmd test
```

The task is complete only when:

- the application compiles;
- all existing tests still pass;
- the new self-share/device-isolation tests pass;
- no cryptographic protocol bytes were changed;
- no installation identifier or private material is exposed;
- the final response lists changed files, migrations, endpoint contracts and
  test totals.
