# Backend Public UUID Contract — Required Fixes

## Target project

Apply these changes in:

`C:\git-repos\File-Drive-Spring`

Inspect the current source before editing. Keep unrelated user changes intact.

## Objective

Finish and validate the permanent user public-UUID contract needed by the future Lockbox sharing protocol.

The current implementation is partially correct:

- `User.publicUuid` exists.
- New users receive `UUID.randomUUID()` through `@PrePersist`.
- Login returns `publicUuid`.
- Refresh returns `publicUuid`.
- Authentication public-UUID contract tests pass.

However, the full backend test suite currently fails, recipient key lookup omits the recipient UUID, and existing users have no safe UUID backfill migration.

Do not implement the Lockbox sharing cryptographic protocol in this task.

## 1. Fix invalid Spring Data repository property paths

File:

`src/main/java/kakha/kudava/filedrivespring/repository/LockboxShareRepository.java`

The current repository contains invalid methods such as:

```java
Optional<LockboxShare> findByLockboxFileIdAndRecipientUserId(
        Long lockboxFileId,
        Long recipientUserId
);

List<LockboxShare> findAllByRecipientUserIdAndStatus(
        Long recipientUserId,
        LockboxShare.Status status
);
```

They prevent the Spring application context from loading because `LockboxShare.recipient` refers to `User`, and the `User` identifier property is named `id`, not `userId`.

The observed failure is:

```text
No property 'userId' found for type 'User'
Traversed path: LockboxShare.recipient
```

If these methods are unused, remove them. Prefer removal when equivalent valid methods already exist.

If they are required, rename them to valid derived queries:

```java
Optional<LockboxShare> findByLockboxFileIdAndRecipientId(
        Long lockboxFileId,
        Long recipientId
);

List<LockboxShare> findAllByRecipientIdAndStatus(
        Long recipientId,
        LockboxShare.Status status
);
```

Before adding either method, inspect the repository for an equivalent existing method such as:

```java
findAllByRecipientIdAndStatusOrderByCreatedAtDesc(...)
```

Do not leave duplicate or unused repository methods.

Update any call sites if a bad method is currently used.

## 2. Include recipient public UUID in key lookup

File:

`src/main/java/kakha/kudava/filedrivespring/dto/lockbox/LockboxRecipientKeysResponse.java`

Replace the record with:

```java
package kakha.kudava.filedrivespring.dto.lockbox;

import java.util.List;
import java.util.UUID;

public record LockboxRecipientKeysResponse(
        Long recipientId,
        UUID recipientPublicUuid,
        String username,
        List<LockboxRecipientKeyResponse> encryptionKeys
) {
}
```

File:

`src/main/java/kakha/kudava/filedrivespring/services/lockbox/LockboxSharingService.java`

Update the recipient-key response construction to include the UUID:

```java
UUID recipientPublicUuid =
        recipient.getPublicUuid();

if (recipientPublicUuid == null) {
    throw recipientUnavailable();
}

return new LockboxRecipientKeysResponse(
        recipient.getId(),
        recipientPublicUuid,
        recipient.getUsername(),
        keyResponses
);
```

Add:

```java
import java.util.UUID;
```

Do not generate a UUID inside the lookup service. A missing persisted UUID is a data-integrity problem, and generating a temporary response UUID would break protocol identity stability.

Preserve the existing behavior that:

- prevents lookup of oneself,
- returns only active ML-KEM-1024 encryption keys,
- returns `404` when the recipient is unavailable,
- does not expose private key material.

The endpoint remains:

```http
GET /api/lockbox/share-recipients/{username}/keys
```

Expected response shape:

```json
{
  "recipientId": 2,
  "recipientPublicUuid": "a33b2748-e1f8-44de-a9c4-a67ca51fa882",
  "username": "gela",
  "encryptionKeys": [
    {
      "keyId": "BASE64_KEY_ID",
      "algorithm": "ML_KEM_1024",
      "publicKey": "BASE64_PUBLIC_KEY"
    }
  ]
}
```

`recipientId` may remain temporarily for existing application usage, but it must not be used as the stable identity in the future signed sharing protocol. `recipientPublicUuid` is the protocol identity.

## 3. Backfill existing user UUIDs safely

`@PrePersist` initializes only newly inserted entities. It does not populate existing rows such as an older `admin` account.

Implement a real migration appropriate to the project. First inspect whether Flyway or Liquibase is already configured. If a migration framework exists, use it. If none exists, add a clearly documented database migration mechanism rather than hiding a permanent data migration in request handling.

The migration must perform these logical steps:

1. Add `users.public_uuid` as nullable.
2. Assign a distinct random UUID to every existing row where it is null.
3. Verify there are no nulls or duplicates.
4. Add a unique constraint/index.
5. Change the column to `NOT NULL`.

Use database-specific syntax that matches the actual production database. The development database is H2, but do not assume H2 syntax is valid for a future PostgreSQL/MySQL deployment.

Do not:

- delete or recreate the users table,
- change an already assigned UUID,
- derive UUIDs from usernames or numeric IDs,
- generate UUIDs during every login,
- silently replace a null UUID only in an API response,
- rely solely on `spring.jpa.hibernate.ddl-auto=update` for populated databases.

The final entity may remain:

```java
@Column(
        name = "public_uuid",
        nullable = false,
        unique = true,
        updatable = false
)
private UUID publicUuid;

@PrePersist
private void beforeInsert() {
    if (publicUuid == null) {
        publicUuid = UUID.randomUUID();
    }
}
```

If `User` already has another `@PrePersist` callback, merge the initialization into that callback instead of creating conflicting lifecycle logic.

## 4. Preserve authentication contracts

Confirm these endpoints continue returning the same stable UUID for a user:

```http
POST /api/auth/login
POST /api/auth/refresh
```

Expected fields:

```json
{
  "accessToken": "...",
  "userId": 1,
  "username": "admin",
  "publicUuid": "8c98baef-9c78-45d3-8797-b27e9786fa26"
}
```

Requirements:

- Login and refresh must return the same persisted UUID.
- Refresh must not generate or mutate it.
- A missing UUID must fail closed and be treated as a server data-integrity error.
- Never place the UUID in place of JWT authentication or authorization checks; it is an identifier, not a credential.

## 5. Tests

Preserve the existing authentication public-UUID tests and add tests for the repaired behavior.

Required coverage:

1. Full Spring application context loads successfully.
2. `LockboxShareRepository` initializes without query-creation errors.
3. Login returns the persisted `publicUuid`.
4. Refresh returns the same persisted `publicUuid`.
5. Recipient-key lookup returns `recipientPublicUuid`.
6. Recipient-key lookup returns the UUID belonging to the selected recipient, not the requester.
7. Recipient with a null UUID is treated as unavailable or produces the chosen stable integrity error.
8. Creating a new user assigns a non-null UUID.
9. Two new users receive distinct UUIDs.
10. Updating a user does not change its UUID.
11. Migration/backfill gives all pre-existing fixture users distinct, non-null UUIDs.

Do not weaken or disable `SftpSpringApplicationTests.contextLoads` to make the build green. The repository error must actually be fixed.

## 6. Verification

Run:

```powershell
mvn.cmd test
```

The previous observed result was:

```text
Tests run: 7, Failures: 0, Errors: 1
BUILD FAILURE
```

The error was caused by:

```text
LockboxShareRepository.findByLockboxFileIdAndRecipientUserId
No property 'userId' found for type 'User'
```

The task is not complete until the entire Maven test suite passes, including the Spring context test.

After tests pass, if the user wants the running Docker backend updated, rebuild only the backend service:

```powershell
docker compose up -d --build app
```

Then verify startup and manually check:

```http
POST /api/auth/login
POST /api/auth/refresh
GET  /api/lockbox/share-recipients/gela/keys
```

## Scope exclusions

Do not implement in this repair task:

- Lockbox share creation
- accept/decline flows
- canonical sharing transcripts
- ML-KEM DEK rewrapping
- ML-DSA share signatures
- shared-file downloads
- client changes

## Completion report

Report:

- repository methods removed or renamed,
- DTO and response changes,
- migration/backfill approach and database assumptions,
- tests added,
- full Maven result,
- whether Docker was rebuilt,
- any remaining data migration action required before deployment.

