package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import kakha.kudava.fdclient.security.DpapiRefreshTokenStore;
import kakha.kudava.fdclient.security.RefreshTokenStore;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.HttpCookie;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

public final class AuthService {

    private static final URI AUTH_URI =
            BackendConfig.uri("/api/auth/");

    private static final URI LOGIN_URI =
            AUTH_URI.resolve("login");

    private static final URI REFRESH_URI =
            AUTH_URI.resolve("refresh");

    private static final String REFRESH_COOKIE_NAME =
            "refresh_token";

    private final ObjectMapper objectMapper =
            new ObjectMapper();

    private final RefreshTokenStore refreshTokenStore;
    private final Runnable clearAccountContext;
    private final java.util.function.LongConsumer activateAccountContext;

    public AuthService() {
        this(new DpapiRefreshTokenStore(), LockboxAccountContext::clear, LockboxAccountContext::activate);
    }

    AuthService(RefreshTokenStore refreshTokenStore, Runnable clearAccountContext,
                java.util.function.LongConsumer activateAccountContext) {
        this.refreshTokenStore = java.util.Objects.requireNonNull(refreshTokenStore);
        this.clearAccountContext = java.util.Objects.requireNonNull(clearAccountContext);
        this.activateAccountContext = java.util.Objects.requireNonNull(activateAccountContext);
    }

    /*
     * Receives and sends the refresh_token cookie.
     * The cookie is held in memory while the application runs.
     */
    private final CookieManager cookieManager =
            new CookieManager(null, CookiePolicy.ACCEPT_ALL);

    private final HttpClient httpClient =
            HttpClient.newBuilder()
                    .connectTimeout(Duration.ofSeconds(10))
                    .cookieHandler(cookieManager)
                    .build();

    /*
     * Access tokens are intentionally kept only in memory.
     */
    private volatile String accessToken;
    private volatile Long userId;
    private volatile String username;
    private volatile UUID publicUuid;
    private volatile String mfaChallenge;
    private volatile Instant mfaExpiresAt;

    public record LoginResult(boolean mfaRequired) {}

    public void cancelMfa() {
        mfaChallenge = null;
        mfaExpiresAt = null;
    }

    public CompletableFuture<LoginResult> login(
            String username,
            String password
    ) {
        if (username == null || username.isBlank()) {
            return CompletableFuture.failedFuture(
                    new AuthException("Username must not be blank.")
            );
        }

        if (password == null || password.isBlank()) {
            return CompletableFuture.failedFuture(
                    new AuthException("Password must not be blank.")
            );
        }

        /*
         * Avoid accidentally using an old cookie if the server fails
         * to return a new refresh token.
         *
         * This does not delete the DPAPI file yet.
         */
        cookieManager.getCookieStore().removeAll();
        cancelMfa();
        accessToken = null;
        userId = null;
        this.username = null;
        publicUuid = null;
        clearAccountContext.run();

        final String requestBody;

        try {
            ObjectNode json = objectMapper.createObjectNode();
            json.put("username", username);
            json.put("password", password);

            requestBody = objectMapper.writeValueAsString(json);
        } catch (Exception exception) {
            return CompletableFuture.failedFuture(exception);
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(LOGIN_URI)
                .timeout(Duration.ofSeconds(20))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        return httpClient.sendAsync(
                        request,
                        HttpResponse.BodyHandlers.ofString()
                )
                .thenApply(this::handleInitialLoginResponse);
    }

    LoginResult handleInitialLoginResponse(HttpResponse<String> response) {
        if (response.statusCode() == 200) {
            try {
                JsonNode json = objectMapper.readTree(response.body());
                if (json.path("mfaRequired").asBoolean(false)) {
                    String challenge = json.path("challengeToken").asText("");
                    Instant expiry = Instant.parse(json.path("expiresAt").asText(""));
                    if (challenge.isBlank() || !expiry.isAfter(Instant.now()) || json.has("accessToken"))
                        throw new AuthException("The server returned an invalid MFA challenge.");
                    // A password challenge must never activate an account or retain old credentials.
                    clearLocalSession();
                    mfaChallenge = challenge;
                    mfaExpiresAt = expiry;
                    return new LoginResult(true);
                }
            } catch (Exception ignored) {
                cancelMfa();
                throw new AuthException("Could not process the login challenge. Start again.");
            }
        }
        handleLoginResponse(response);
        return new LoginResult(false);
    }

    public CompletableFuture<String> completeMfa(String code) {
        String challenge = mfaChallenge;
        Instant expiry = mfaExpiresAt;
        if (challenge == null || expiry == null || !expiry.isAfter(Instant.now())) {
            cancelMfa();
            return CompletableFuture.failedFuture(new AuthException("Login challenge expired. Start again."));
        }
        if (code == null || !code.matches("[0-9]{6}"))
            return CompletableFuture.failedFuture(new AuthException("Enter exactly six digits."));
        ObjectNode body = objectMapper.createObjectNode().put("challengeToken", challenge).put("code", code);
        HttpRequest request = HttpRequest.newBuilder(AUTH_URI.resolve("mfa/totp"))
                .timeout(Duration.ofSeconds(20)).header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString())).build();
        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString()).thenApply(this::handleMfaResponse);
    }

    String handleMfaResponse(HttpResponse<String> response) {
            if (response.statusCode() != 200) {
                throw new AuthException(response.statusCode() == 429 ? "Too many attempts. Try again later."
                        : "Code rejected or challenge expired. Try a fresh code, or start again.");
            }
            String token = handleLoginResponse(response);
            cancelMfa();
            return token;
    }

    private String handleLoginResponse(
            HttpResponse<String> response
    ) {
        if (response.statusCode() == 200) {
            try {
                JsonNode json =
                        objectMapper.readTree(response.body());

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

                if (newAccessToken.isBlank() || newUserId < 1 || newUsername.isBlank()) {
                    throw new AuthException(
                            "The server did not return a complete account session."
                    );
                }

                /*
                 * Save the refresh token first.
                 *
                 * If DPAPI storage fails, login fails cleanly rather
                 * than leaving a partially initialized local session.
                 */
                saveRefreshTokenFromCookieStore();

                activateAccountContext.accept(newUserId);
                userId = newUserId;
                username = newUsername;
                publicUuid = newPublicUuid;
                accessToken = newAccessToken;
                return newAccessToken;
            } catch (AuthException exception) {
                throw exception;
            } catch (Exception exception) {
                throw new AuthException("Could not process the login response.");
            }
        }

        if (response.statusCode() == 401
                || response.statusCode() == 403) {
            throw new AuthException(
                    "Incorrect username or password."
            );
        }

        throw new AuthException(
                "Login failed. Server returned HTTP "
                        + response.statusCode()
                        + "."
        );
    }

    /**
     * Restores the refresh token from the DPAPI-protected file and
     * exchanges it for a new access token.
     *
     * @return true when a session was restored, or false when no
     * saved refresh token exists
     */
    public CompletableFuture<Boolean> restoreSession() {
        final Optional<String> savedToken;

        try {
            savedToken = refreshTokenStore.load();
        } catch (RuntimeException exception) {
            return CompletableFuture.failedFuture(exception);
        }

        if (savedToken.isEmpty()) {
            return CompletableFuture.completedFuture(false);
        }

        restoreRefreshCookie(savedToken.get());

        return refresh()
                .thenApply(newAccessToken -> true);
    }

    public CompletableFuture<String> refresh() {
        HttpRequest request = HttpRequest.newBuilder()
                .uri(REFRESH_URI)
                .timeout(Duration.ofSeconds(20))
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

        return httpClient.sendAsync(
                        request,
                        HttpResponse.BodyHandlers.ofString()
                )
                .thenApply(this::handleRefreshResponse);
    }

    private String handleRefreshResponse(
            HttpResponse<String> response
    ) {
        if (response.statusCode() == 200) {
            try {
                JsonNode json =
                        objectMapper.readTree(response.body());

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

                if (newAccessToken.isBlank() || refreshedUserId < 1 || refreshedUsername.isBlank()) {
                    throw new AuthException(
                            "The server returned an incomplete refreshed session."
                    );
                }

                /*
                 * The backend rotates refresh tokens.
                 *
                 * CookieManager has received the replacement cookie,
                 * so save the new token before updating session state.
                 */
                saveRefreshTokenFromCookieStore();

                activateAccountContext.accept(refreshedUserId);
                userId = refreshedUserId;
                username = refreshedUsername;
                publicUuid = refreshedPublicUuid;
                accessToken = newAccessToken;
                return newAccessToken;
            } catch (AuthException exception) {
                throw exception;
            } catch (Exception exception) {
                throw new CompletionException(
                        "Could not process the refresh response.",
                        exception
                );
            }
        }

        if (response.statusCode() == 401
                || response.statusCode() == 403) {
            clearLocalSessionAfterAuthFailure();

            throw new AuthException(
                    "Your saved session has expired. Log in again."
            );
        }

        throw new AuthException(
                "Could not refresh the session. HTTP "
                        + response.statusCode()
                        + ". Response: "
                        + response.body()
        );
    }

    /**
     * Finds the refresh cookie that applies specifically to the
     * refresh endpoint.
     */
    private Optional<HttpCookie> findRefreshCookie() {
        return cookieManager
                .getCookieStore()
                .get(REFRESH_URI)
                .stream()
                .filter(cookie ->
                        REFRESH_COOKIE_NAME.equals(cookie.getName())
                )
                .filter(cookie -> !cookie.hasExpired())
                .filter(cookie ->
                        cookie.getValue() != null
                                && !cookie.getValue().isBlank()
                )
                .findFirst();
    }

    private void saveRefreshTokenFromCookieStore() {
        HttpCookie refreshCookie = findRefreshCookie()
                .orElseThrow(() -> new AuthException(
                        "The server did not return a refresh token."
                ));

        refreshTokenStore.save(refreshCookie.getValue());
    }

    /**
     * Reconstructs the refresh cookie in the in-memory CookieManager.
     *
     * The token itself was loaded from the DPAPI-protected file.
     */
    private void restoreRefreshCookie(String refreshToken) {
        HttpCookie cookie = new HttpCookie(
                REFRESH_COOKIE_NAME,
                refreshToken
        );

        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/api/auth");
        cookie.setVersion(0);

        cookieManager.getCookieStore().removeAll();
        cookieManager.getCookieStore().add(AUTH_URI, cookie);
    }

    static UUID parsePublicUuid(
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

    /**
     * Explicit local logout.
     *
     * This method reports token-file deletion failures to the caller.
     */
    public void clearLocalSession() {
        cancelMfa();
        accessToken = null;
        userId = null;
        username = null;
        publicUuid = null;
        clearAccountContext.run();
        cookieManager.getCookieStore().removeAll();
        refreshTokenStore.delete();
    }

    /**
     * Cleanup used after the server rejects a refresh token.
     *
     * Failure to delete the local file must not hide the original
     * authentication error.
     */
    private void clearLocalSessionAfterAuthFailure() {
        accessToken = null;
        userId = null;
        username = null;
        publicUuid = null;
        clearAccountContext.run();
        cookieManager.getCookieStore().removeAll();

        try {
            refreshTokenStore.delete();
        } catch (RuntimeException exception) {
            System.err.println(
                    "Could not delete the stored refresh token: "
                            + exception.getMessage()
            );
        }
    }

    public String getAccessToken() {
        return accessToken;
    }

    public long getUserId() {
        Long value = userId;
        if (value == null) throw new IllegalStateException("No authenticated account ID is available.");
        return value;
    }

    public String getUsername() {
        return username;
    }

    public UUID getPublicUuid() {
        UUID value = publicUuid;

        if (value == null) {
            throw new IllegalStateException(
                    "No authenticated account public UUID is available."
            );
        }

        return value;
    }

    public Optional<String> accessToken() {
        return Optional.ofNullable(accessToken);
    }

    public boolean isAuthenticated() {
        return accessToken != null
                && !accessToken.isBlank()
                && userId != null
                && username != null
                && !username.isBlank()
                && publicUuid != null;
    }

    public CookieManager getCookieManager() {
        return cookieManager;
    }

    public static final class AuthException
            extends RuntimeException {

        public AuthException(String message) {
            super(message);
        }
    }
}
