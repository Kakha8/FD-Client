# FD-Client: Authenticated Account Public UUID

## Objective

Update the Java desktop client at:

`C:\git-repos\FD-Client`

The client must receive, validate, retain, and expose the authenticated user's permanent public UUID returned by the backend during login and refresh.

This UUID will later be used as the stable owner identity in the Lockbox sharing protocol. This task does **not** define or implement the cryptographic sharing transcript.

## Backend prerequisite

Confirm that both backend responses include `publicUuid`:

```json
{
  "accessToken": "...",
  "userId": 1,
  "username": "admin",
  "publicUuid": "8c98baef-9c78-45d3-8797-b27e9786fa26"
}
```

Required backend endpoints:

- `POST /api/auth/login`
- `POST /api/auth/refresh`

Do not add client fallback behavior for a missing UUID. A successful authentication response without a valid `publicUuid` is an incomplete session and must fail closed.

## Primary file

Modify:

`src/main/java/kakha/kudava/fdclient/service/AuthService.java`

Inspect the current file before editing. Preserve its existing cookie handling, DPAPI refresh-token storage, account-scoped Lockbox activation, asynchronous HTTP behavior, and error handling.

## Required changes

### 1. Import UUID

Add:

```java
import java.util.UUID;
```

### 2. Add session state

Alongside `accessToken`, `userId`, and `username`, add:

```java
private volatile UUID publicUuid;
```

The UUID is public identity metadata, not a secret. It should remain in memory as part of the authenticated session. Do not use it as the local account-directory selector; keep the existing `userId`-based `LockboxAccountContext` behavior unchanged for this task.

### 3. Clear it before a new login

In `login(String username, String password)`, the existing pre-login reset must include:

```java
publicUuid = null;
```

Be careful with the existing method parameter named `username`. The field reset must remain:

```java
this.username = null;
```

Do not reintroduce the previous shadowing bug by assigning `username = null`, which would erase the method parameter and send a null username to the backend.

The complete state-reset portion should remain logically equivalent to:

```java
cookieManager.getCookieStore().removeAll();
accessToken = null;
userId = null;
this.username = null;
publicUuid = null;
LockboxAccountContext.clear();
```

### 4. Add strict UUID parsing

Add a private helper:

```java
private UUID parsePublicUuid(
        String value
) {
    if (value == null || value.isBlank()) {
        throw new AuthException(
                "The server did not return an account public UUID."
        );
    }

    try {
        return UUID.fromString(value);
    } catch (IllegalArgumentException exception) {
        throw new AuthException(
                "The server returned an invalid account public UUID."
        );
    }
}
```

Use Java's canonical UUID parser. Do not silently generate a replacement UUID on the client. The backend-issued stable UUID is authoritative.

### 5. Replace login-response processing

Update `handleLoginResponse(HttpResponse<String> response)` so its successful-response branch reads:

```java
String newAccessToken =
        json.path("accessToken").asText("");

long newUserId =
        json.path("userId").asLong(-1);

String newUsername =
        json.path("username").asText("");

UUID newPublicUuid =
        parsePublicUuid(
                json.path("publicUuid").asText("")
        );
```

Retain validation of the token, numeric user ID, and username. Parse and validate every value before mutating authenticated session state.

After the refresh token has been saved successfully, establish state in this order or an equivalently safe order:

```java
LockboxAccountContext.activate(newUserId);
userId = newUserId;
username = newUsername;
publicUuid = newPublicUuid;
accessToken = newAccessToken;
```

Set `accessToken` last so `isAuthenticated()` cannot observe a partially initialized session.

Preserve existing handling for `401`, `403`, and other HTTP statuses.

### 6. Replace refresh-response processing

Update `handleRefreshResponse(HttpResponse<String> response)` in the same way:

```java
String newAccessToken =
        json.path("accessToken").asText("");

long refreshedUserId =
        json.path("userId").asLong(-1);

String refreshedUsername =
        json.path("username").asText("");

UUID refreshedPublicUuid =
        parsePublicUuid(
                json.path("publicUuid").asText("")
        );
```

After saving the rotated refresh token:

```java
LockboxAccountContext.activate(refreshedUserId);
userId = refreshedUserId;
username = refreshedUsername;
publicUuid = refreshedPublicUuid;
accessToken = newAccessToken;
```

This must also cover `restoreSession()`, because restoration already calls `refresh()`.

### 7. Clear UUID on every session teardown

Add:

```java
publicUuid = null;
```

to both:

- `clearLocalSession()`
- `clearLocalSessionAfterAuthFailure()`

Search for every other location that clears `accessToken`, `userId`, or `username`. Ensure `publicUuid` is cleared there too.

### 8. Add a strict getter

Add:

```java
public UUID getPublicUuid() {
    UUID value = publicUuid;

    if (value == null) {
        throw new IllegalStateException(
                "No authenticated account public UUID is available."
        );
    }

    return value;
}
```

Do not return `null` from this getter.

### 9. Strengthen authentication state

Update `isAuthenticated()` so it requires a complete session:

```java
public boolean isAuthenticated() {
    return accessToken != null
            && !accessToken.isBlank()
            && userId != null
            && username != null
            && !username.isBlank()
            && publicUuid != null;
}
```

## Tests

Add focused tests for the authentication response contract. Refactor response parsing only as much as necessary to make it testable; do not redesign the entire HTTP layer.

Cover at least:

1. Valid login response stores `accessToken`, `userId`, `username`, and `publicUuid`.
2. Valid refresh response updates all four session fields.
3. Missing `publicUuid` rejects the response.
4. Blank `publicUuid` rejects the response.
5. Malformed `publicUuid` rejects the response.
6. Session clear removes `publicUuid`.
7. Authentication-failure cleanup removes `publicUuid`.
8. `isAuthenticated()` is false for partial session state.
9. The entered login username is still included in the JSON request; specifically guard against the prior field-shadowing regression.

Do not require live backend access in unit tests. Avoid persisting test refresh tokens into the real user's DPAPI location; inject or substitute test-safe collaborators if needed.

## Verification

Run:

```powershell
mvn.cmd test
```

Then manually verify against the rebuilt backend:

1. Log in normally.
2. Confirm login opens the main page.
3. Restart the client.
4. Confirm refresh-token session restoration succeeds.
5. Log out and confirm the session is cleared.
6. Log in as a second account and confirm the correct account context is activated.

## Scope boundaries

Do not implement these in this task:

- the sharing-envelope format
- a canonical sharing transcript
- ML-KEM DEK rewrapping
- ML-DSA sharing signatures
- recipient-key lookup UI
- create-share API calls
- changes to Rust native key storage
- replacement of local `userId` account directories with UUID directories

## Completion report

When finished, report:

- files changed
- exact backend JSON field consumed
- tests added and their result
- manual verification performed
- any backend contract mismatch encountered

