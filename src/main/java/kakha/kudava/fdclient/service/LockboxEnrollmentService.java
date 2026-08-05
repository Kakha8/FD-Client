package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

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
