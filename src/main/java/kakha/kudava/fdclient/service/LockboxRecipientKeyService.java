package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

public final class LockboxRecipientKeyService {

    private static final URI RECIPIENTS_URI = URI.create(
            "https://localhost:8443/api/lockbox/share-recipients/"
    );

    private static final int KEY_ID_LENGTH = 32;
    private static final int ML_KEM_1024_PUBLIC_KEY_LENGTH = 1_568;
    private static final int MAX_RESPONSE_CHARACTERS = 100_000;

    private static final ObjectMapper JSON = new ObjectMapper();

    private final AuthService authService;
    private final HttpClient httpClient;

    public LockboxRecipientKeyService(
            AuthService authService
    ) {
        this(
                authService,
                HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(10))
                        .build()
        );
    }

    LockboxRecipientKeyService(
            AuthService authService,
            HttpClient httpClient
    ) {
        this.authService = Objects.requireNonNull(
                authService,
                "authService"
        );
        this.httpClient = Objects.requireNonNull(
                httpClient,
                "httpClient"
        );
    }

    public CompletableFuture<LockboxRecipientKeys> lookup(
            String username
    ) {
        final String normalizedUsername;

        try {
            normalizedUsername = normalizeUsername(username);
        } catch (RuntimeException exception) {
            return CompletableFuture.failedFuture(exception);
        }

        if (!authService.isAuthenticated()) {
            return CompletableFuture.failedFuture(
                    new RecipientKeyException(
                            "Log in before selecting a share recipient."
                    )
            );
        }

        String encodedUsername = URLEncoder.encode(
                        normalizedUsername,
                        StandardCharsets.UTF_8
                )
                .replace("+", "%20");

        URI requestUri = RECIPIENTS_URI.resolve(
                encodedUsername + "/keys"
        );

        HttpRequest request = HttpRequest.newBuilder()
                .uri(requestUri)
                .timeout(Duration.ofSeconds(20))
                .header(
                        "Authorization",
                        "Bearer " + authService.getAccessToken()
                )
                .header("Accept", "application/json")
                .GET()
                .build();

        return httpClient.sendAsync(
                        request,
                        HttpResponse.BodyHandlers.ofString(
                                StandardCharsets.UTF_8
                        )
                )
                .thenApply(response ->
                        handleResponse(
                                response,
                                normalizedUsername
                        )
                );
    }

    private LockboxRecipientKeys handleResponse(
            HttpResponse<String> response,
            String requestedUsername
    ) {
        int status = response.statusCode();

        if (status == 200) {
            return parseResponse(
                    response.body(),
                    requestedUsername
            );
        }

        if (status == 401 || status == 403) {
            throw new RecipientKeyException(
                    "Your session is no longer authorized. Log in again."
            );
        }

        if (status == 404) {
            throw new RecipientKeyException(
                    "The Lockbox recipient is unavailable."
            );
        }

        throw new RecipientKeyException(
                "Recipient key lookup failed with HTTP " + status + "."
        );
    }

    static LockboxRecipientKeys parseResponse(
            String body,
            String requestedUsername
    ) {
        if (body == null
                || body.isBlank()
                || body.length() > MAX_RESPONSE_CHARACTERS) {
            throw invalidResponse();
        }

        try {
            JsonNode root = JSON.readTree(body);

            long recipientId = root.path("recipientId").asLong(-1);

            UUID recipientPublicUuid = parseUuid(
                    root.path("recipientPublicUuid").asText("")
            );

            String responseUsername = normalizeUsername(
                    root.path("username").asText("")
            );

            if (!responseUsername.equals(requestedUsername)) {
                throw invalidResponse();
            }

            JsonNode keysNode = root.path("encryptionKeys");

            if (!keysNode.isArray() || keysNode.isEmpty()) {
                throw invalidResponse();
            }

            List<LockboxRecipientEncryptionKey> keys =
                    new ArrayList<>(keysNode.size());

            for (JsonNode keyNode : keysNode) {
                String algorithm =
                        keyNode.path("algorithm").asText("");

                if (!"ML_KEM_1024".equals(algorithm)) {
                    throw invalidResponse();
                }

                byte[] keyId = decodeExact(
                        keyNode.path("keyId").asText(""),
                        KEY_ID_LENGTH
                );

                byte[] publicKey = decodeExact(
                        keyNode.path("publicKey").asText(""),
                        ML_KEM_1024_PUBLIC_KEY_LENGTH
                );

                keys.add(
                        new LockboxRecipientEncryptionKey(
                                keyId,
                                LockboxRecipientEncryptionKey.Algorithm
                                        .ML_KEM_1024,
                                publicKey
                        )
                );
            }

            return new LockboxRecipientKeys(
                    recipientId,
                    recipientPublicUuid,
                    responseUsername,
                    keys
            );
        } catch (RecipientKeyException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new CompletionException(
                    "Could not process the recipient key response.",
                    exception
            );
        }
    }

    private static byte[] decodeExact(
            String encoded,
            int expectedLength
    ) {
        final byte[] decoded;

        try {
            decoded = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException exception) {
            throw invalidResponse();
        }

        if (decoded.length != expectedLength) {
            throw invalidResponse();
        }

        return decoded;
    }

    private static UUID parseUuid(
            String value
    ) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            throw invalidResponse();
        }
    }

    private static String normalizeUsername(
            String username
    ) {
        if (username == null) {
            throw new RecipientKeyException(
                    "Enter a recipient username."
            );
        }

        String normalized = username.trim();

        if (normalized.isEmpty() || normalized.length() > 100) {
            throw new RecipientKeyException(
                    "Enter a valid recipient username."
            );
        }

        return normalized;
    }

    private static RecipientKeyException invalidResponse() {
        return new RecipientKeyException(
                "The server returned an invalid recipient key response."
        );
    }

    public static final class RecipientKeyException
            extends RuntimeException {

        public RecipientKeyException(
                String message
        ) {
            super(message);
        }
    }
}
