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
            URI.create(
                    "https://localhost:8443/api/lockbox/enrollments"
            );

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
            String accessToken
    ) {
        if (accessToken == null || accessToken.isBlank()) {
            return CompletableFuture.failedFuture(
                    new EnrollmentException(
                            "No authenticated session is available."
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
                .POST(HttpRequest.BodyPublishers.noBody())
                .build();

        return httpClient.sendAsync(
                        request,
                        HttpResponse.BodyHandlers.ofString(
                                StandardCharsets.UTF_8
                        )
                )
                .thenApply(this::readChallenge);
    }

    public CompletableFuture<EnrollmentResult> completeEnrollment(
            String accessToken,
            EnrollmentChallenge challenge,
            UUID deviceId,
            String deviceName
    ) {
        if (accessToken == null || accessToken.isBlank()) {
            return CompletableFuture.failedFuture(
                    new EnrollmentException("No authenticated session is available.")
            );
        }

        return CompletableFuture.supplyAsync(() -> enrollmentCrypto.createProof(
                challenge.enrollmentId(), challenge.challenge(), challenge.expiresAt(),
                deviceId, deviceName
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
            HttpResponse<String> response
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
                        )
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
            Instant expiresAt
    ) {
        public EnrollmentChallenge {
            Objects.requireNonNull(enrollmentId, "enrollmentId");
            Objects.requireNonNull(expiresAt, "expiresAt");

            if (challenge == null || challenge.isBlank()) {
                throw new IllegalArgumentException(
                        "Enrollment challenge is required."
                );
            }
        }
    }

    public record EnrollmentResult(
            String lockboxStatus,
            String deviceStatus,
            UUID deviceId
    ) {}

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
