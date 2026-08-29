package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import kakha.kudava.fdclient.crypto.LockboxEnrollmentCrypto;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/** Starts the authenticated Lockbox device-enrollment protocol. */
public final class LockboxEnrollmentService {

    private static final URI ENROLLMENT_URI =
            BackendConfig.uri("/api/lockbox/enrollments");

    private static final Duration CONNECT_TIMEOUT =
            Duration.ofSeconds(15);

    private static final Duration REQUEST_TIMEOUT =
            Duration.ofSeconds(30);

    private final ObjectMapper objectMapper =
            new ObjectMapper();

    private final HttpClient httpClient =
            HttpClient.newBuilder()
                    .connectTimeout(CONNECT_TIMEOUT)
                    .build();

    private final LockboxEnrollmentCrypto enrollmentCrypto =
            new LockboxEnrollmentCrypto();

    public CompletableFuture<EnrollmentChallenge> beginEnrollment(
            String accessToken,
            UUID deviceId,
            String installationHandle,
            String deviceName
    ) {
        if (accessToken == null || accessToken.isBlank()) {
            return CompletableFuture.failedFuture(
                    new EnrollmentException(
                            "No authenticated session is available."
                    )
            );
        }

        Objects.requireNonNull(deviceId, "deviceId");
        requireInstallationHandle(installationHandle);
        String normalizedDeviceName = requireDeviceName(deviceName);

        final String requestBody;
        try {
            requestBody = objectMapper.writeValueAsString(
                    objectMapper.createObjectNode()
                            .put("deviceId", deviceId.toString())
                            .put("installationHandle", installationHandle)
                            .put("deviceName", normalizedDeviceName)
            );
        } catch (Exception exception) {
            return CompletableFuture.failedFuture(
                    new EnrollmentException(
                            "Could not create the enrollment request.",
                            exception
                    )
            );
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(ENROLLMENT_URI)
                .timeout(REQUEST_TIMEOUT)
                .header(
                        "Authorization",
                        "Bearer " + accessToken
                )
                .header("Accept", "application/json")
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(
                        requestBody,
                        StandardCharsets.UTF_8
                ))
                .build();

        return httpClient.sendAsync(
                        request,
                        HttpResponse.BodyHandlers.ofString(
                                StandardCharsets.UTF_8
                        )
                )
                .thenApply(response -> readChallenge(
                        response,
                        deviceId,
                        installationHandle,
                        normalizedDeviceName
                ));
    }

    public CompletableFuture<LockboxStatus> getStatus(
            String accessToken,
            UUID deviceId
    ) {
        if (accessToken == null || accessToken.isBlank()) {
            return CompletableFuture.failedFuture(
                    new EnrollmentException("No authenticated session is available.")
            );
        }
        Objects.requireNonNull(deviceId, "deviceId");

        URI statusUri = URI.create(
                ENROLLMENT_URI + "/status?deviceId=" + deviceId
        );
        HttpRequest request = HttpRequest.newBuilder()
                .uri(statusUri)
                .timeout(REQUEST_TIMEOUT)
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET()
                .build();

        return httpClient.sendAsync(
                        request,
                        HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8)
                )
                .thenApply(this::readStatus);
    }

    private LockboxStatus readStatus(HttpResponse<String> response) {
        if (response.statusCode() == 200) {
            try {
                JsonNode json = objectMapper.readTree(response.body());
                return new LockboxStatus(
                        AccountStatus.valueOf(requireText(json, "lockboxStatus")),
                        DeviceStatus.valueOf(requireText(json, "deviceStatus")),
                        UUID.fromString(requireText(json, "deviceId"))
                );
            } catch (Exception exception) {
                throw new CompletionException(
                        new EnrollmentException(
                                "The server returned an invalid Lockbox status.",
                                exception
                        )
                );
            }
        }
        if (response.statusCode() == 401 || response.statusCode() == 403) {
            throw new EnrollmentException(
                    "Your session is no longer authorized. Log in again."
            );
        }
        throw new EnrollmentException(
                "Could not check Lockbox status. HTTP "
                        + response.statusCode()
                        + responseDetails(response.body())
        );
    }

    public CompletableFuture<EnrollmentResult> completeEnrollment(
            String accessToken,
            EnrollmentChallenge challenge
    ) {
        if (accessToken == null || accessToken.isBlank()) {
            return CompletableFuture.failedFuture(
                    new EnrollmentException("No authenticated session is available.")
            );
        }
        Objects.requireNonNull(challenge, "challenge");

        return CompletableFuture.supplyAsync(() -> enrollmentCrypto.createProof(
                challenge.enrollmentId(), challenge.challenge(), challenge.expiresAt(),
                challenge.deviceId(), challenge.installationHandle(), challenge.deviceName()
        )).thenCompose(proof -> sendCompletion(accessToken, challenge.enrollmentId(), proof));
    }

    private CompletableFuture<EnrollmentResult> sendCompletion(
            String accessToken,
            UUID enrollmentId,
            LockboxEnrollmentCrypto.EnrollmentProof proof
    ) {
        try {
            JsonNode body = objectMapper.createObjectNode()
                    .put("challenge", proof.challenge())
                    .put("deviceId", proof.deviceId().toString())
                    .put("installationHandle", proof.installationHandle())
                    .put("deviceName", proof.deviceName())
                    .set("encryptionKey", objectMapper.createObjectNode()
                            .put("algorithm", "ML_KEM_1024")
                            .put("keyId", proof.encryptionKeyId())
                            .put("publicKey", proof.encryptionPublicKey()));
            ((com.fasterxml.jackson.databind.node.ObjectNode) body)
                    .set("signingKey", objectMapper.createObjectNode()
                            .put("algorithm", "ML_DSA_87")
                            .put("keyId", proof.signingKeyId())
                            .put("publicKey", proof.signingPublicKey()));
            ((com.fasterxml.jackson.databind.node.ObjectNode) body)
                    .put("signature", proof.signature());

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(ENROLLMENT_URI + "/" + enrollmentId + "/complete"))
                    .timeout(REQUEST_TIMEOUT)
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/json")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            objectMapper.writeValueAsString(body), StandardCharsets.UTF_8))
                    .build();

            return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                    .thenApply(this::readCompletion)
                    .thenApply(result -> {
                        if (!proof.deviceId().equals(result.deviceId())) {
                            throw new EnrollmentException(
                                    "The server returned a different Lockbox device ID.");
                        }
                        return result;
                    });
        } catch (Exception e) {
            return CompletableFuture.failedFuture(
                    new EnrollmentException("Could not create the enrollment completion request.", e));
        }
    }

    private EnrollmentResult readCompletion(HttpResponse<String> response) {
        if (response.statusCode() == 200) {
            try {
                JsonNode json = objectMapper.readTree(response.body());
                return new EnrollmentResult(
                        requireText(json, "lockboxStatus"),
                        requireText(json, "deviceStatus"),
                        UUID.fromString(requireText(json, "deviceId"))
                );
            } catch (Exception e) {
                throw new CompletionException(new EnrollmentException(
                        "The server returned an invalid enrollment result.", e));
            }
        }
        if (response.statusCode() == 401 || response.statusCode() == 403) {
            throw new EnrollmentException("Your session is no longer authorized. Log in again.");
        }
        throw new EnrollmentException("Could not complete Lockbox enrollment. HTTP "
                + response.statusCode() + responseDetails(response.body()));
    }

    private EnrollmentChallenge readChallenge(
            HttpResponse<String> response,
            UUID deviceId,
            String installationHandle,
            String deviceName
    ) {
        if (response.statusCode() == 201) {
            try {
                JsonNode json =
                        objectMapper.readTree(response.body());

                return new EnrollmentChallenge(
                        UUID.fromString(
                                json.path("enrollmentId").asText()
                        ),
                        requireText(json, "challenge"),
                        Instant.parse(
                                requireText(json, "expiresAt")
                        ),
                        deviceId,
                        installationHandle,
                        deviceName
                );
            } catch (Exception exception) {
                throw new CompletionException(
                        new EnrollmentException(
                                "The server returned an invalid enrollment challenge.",
                                exception
                        )
                );
            }
        }

        if (response.statusCode() == 401
                || response.statusCode() == 403) {
            throw new EnrollmentException(
                    "Your session is no longer authorized. Log in again."
            );
        }

        if (response.statusCode() == 409) {
            throw new EnrollmentException(
                    "Lockbox is already enabled for this account."
            );
        }

        throw new EnrollmentException(
                "Could not start Lockbox enrollment. HTTP "
                        + response.statusCode()
                        + responseDetails(response.body())
        );
    }

    private String requireText(JsonNode json, String field) {
        String value = json.path(field).asText();

        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    "Missing response field: " + field
            );
        }

        return value;
    }

    private static void requireInstallationHandle(String value) {
        try {
            byte[] decoded = java.util.Base64.getDecoder().decode(value);
            if (decoded.length != 32
                    || !java.util.Base64.getEncoder().encodeToString(decoded).equals(value)) {
                throw new IllegalArgumentException();
            }
        } catch (RuntimeException exception) {
            throw new EnrollmentException(
                    "The installation handle must be canonical Base64 for exactly 32 bytes."
            );
        }
    }

    private static String requireDeviceName(String value) {
        if (value == null || value.isBlank()) {
            throw new EnrollmentException("Device name is required.");
        }
        String normalized = value.trim();
        if (normalized.length() > 100
                || normalized.getBytes(StandardCharsets.UTF_8).length > 255) {
            throw new EnrollmentException("Device name is too long.");
        }
        return normalized;
    }

    private String responseDetails(String body) {
        if (body == null || body.isBlank()) {
            return ".";
        }

        String compact = body
                .replace('\r', ' ')
                .replace('\n', ' ')
                .trim();

        if (compact.length() > 1_000) {
            compact = compact.substring(0, 1_000) + "...";
        }

        return ". Response: " + compact;
    }

    public record EnrollmentChallenge(
            UUID enrollmentId,
            String challenge,
            Instant expiresAt,
            UUID deviceId,
            String installationHandle,
            String deviceName
    ) {
        public EnrollmentChallenge {
            Objects.requireNonNull(enrollmentId, "enrollmentId");
            Objects.requireNonNull(expiresAt, "expiresAt");
            Objects.requireNonNull(deviceId, "deviceId");

            if (challenge == null || challenge.isBlank()) {
                throw new IllegalArgumentException(
                        "Enrollment challenge is required."
                );
            }
            requireInstallationHandle(installationHandle);
            deviceName = requireDeviceName(deviceName);
        }
    }

    public record EnrollmentResult(
            String lockboxStatus,
            String deviceStatus,
            UUID deviceId
    ) {}

    public record LockboxStatus(
            AccountStatus lockboxStatus,
            DeviceStatus deviceStatus,
            UUID deviceId
    ) {
        public LockboxStatus {
            Objects.requireNonNull(lockboxStatus, "lockboxStatus");
            Objects.requireNonNull(deviceStatus, "deviceStatus");
            Objects.requireNonNull(deviceId, "deviceId");
        }
    }

    public enum AccountStatus {
        NOT_ENABLED,
        ENABLED,
        SUSPENDED
    }

    public enum DeviceStatus {
        NOT_REGISTERED,
        PENDING,
        ACTIVE,
        REVOKED
    }

    public static final class EnrollmentException
            extends RuntimeException {

        public EnrollmentException(String message) {
            super(message);
        }

        public EnrollmentException(
                String message,
                Throwable cause
        ) {
            super(message, cause);
        }
    }
}
