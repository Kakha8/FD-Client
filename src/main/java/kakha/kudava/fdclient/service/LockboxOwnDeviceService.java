package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
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

public final class LockboxOwnDeviceService {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final int MAX_RESPONSE_CHARACTERS = 500_000;
    private final AuthService auth;
    private final HttpClient http;

    public LockboxOwnDeviceService(AuthService auth) {
        this(auth, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    LockboxOwnDeviceService(AuthService auth, HttpClient http) {
        this.auth = Objects.requireNonNull(auth, "auth");
        this.http = Objects.requireNonNull(http, "http");
    }

    public CompletableFuture<List<LockboxOwnDevice>> listOtherDevices(UUID currentDeviceId) {
        if (!auth.isAuthenticated()) {
            return CompletableFuture.failedFuture(
                    new OwnDeviceException("Log in before selecting another device."));
        }
        Objects.requireNonNull(currentDeviceId, "currentDeviceId");
        URI uri = BackendConfig.uri(
                "/api/lockbox/devices?excludeDeviceId=" + currentDeviceId);
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + auth.getAccessToken())
                .header("Accept", "application/json")
                .GET().build();
        return http.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                .thenApply(response -> handle(response));
    }

    private static List<LockboxOwnDevice> handle(HttpResponse<String> response) {
        if (response.statusCode() == 200) return parseResponse(response.body());
        if (response.statusCode() == 401 || response.statusCode() == 403) {
            throw new OwnDeviceException("Your session is no longer authorized. Log in again.");
        }
        throw new OwnDeviceException(
                "Device lookup failed with HTTP " + response.statusCode() + ".");
    }

    static List<LockboxOwnDevice> parseResponse(String body) {
        if (body == null || body.isBlank() || body.length() > MAX_RESPONSE_CHARACTERS) {
            throw invalidResponse();
        }
        try {
            JsonNode devices = JSON.readTree(body).path("devices");
            if (!devices.isArray()) throw invalidResponse();
            List<LockboxOwnDevice> result = new ArrayList<>(devices.size());
            for (JsonNode device : devices) {
                UUID deviceId = UUID.fromString(required(device, "deviceId"));
                String name = required(device, "deviceName").trim();
                if (!"ACTIVE".equals(required(device, "deviceStatus"))) throw invalidResponse();
                JsonNode keys = device.path("encryptionKeys");
                if (!keys.isArray() || keys.isEmpty()) throw invalidResponse();
                List<LockboxRecipientEncryptionKey> encryptionKeys = new ArrayList<>(keys.size());
                for (JsonNode key : keys) {
                    if (!"ML_KEM_1024".equals(required(key, "algorithm"))) {
                        throw invalidResponse();
                    }
                    encryptionKeys.add(new LockboxRecipientEncryptionKey(
                            decodeExact(required(key, "keyId"), 32),
                            LockboxRecipientEncryptionKey.Algorithm.ML_KEM_1024,
                            decodeExact(required(key, "publicKey"), 1_568)));
                }
                result.add(new LockboxOwnDevice(deviceId, name, encryptionKeys));
            }
            return List.copyOf(result);
        } catch (OwnDeviceException error) {
            throw error;
        } catch (Exception error) {
            throw new OwnDeviceException("The server returned an invalid device response.", error);
        }
    }

    private static byte[] decodeExact(String value, int length) {
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            if (decoded.length != length
                    || !Base64.getEncoder().encodeToString(decoded).equals(value)) {
                throw invalidResponse();
            }
            return decoded;
        } catch (IllegalArgumentException error) {
            throw invalidResponse();
        }
    }

    private static String required(JsonNode node, String field) {
        String value = node.path(field).asText("");
        if (value.isBlank()) throw invalidResponse();
        return value;
    }

    private static OwnDeviceException invalidResponse() {
        return new OwnDeviceException("The server returned an invalid device response.");
    }

    public static final class OwnDeviceException extends RuntimeException {
        public OwnDeviceException(String message) { super(message); }
        public OwnDeviceException(String message, Throwable cause) { super(message, cause); }
    }
}
