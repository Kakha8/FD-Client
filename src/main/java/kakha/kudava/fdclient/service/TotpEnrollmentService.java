package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.CompletableFuture;

/** Explicit enrollment requests only: no automatic retries or token refresh on failure. */
public final class TotpEnrollmentService {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private static final URI BASE = BackendConfig.uri("/api/mfa/totp/enrollments");

    public record Pending(long deviceId, String displayName, Instant expiresAt) {}

    public CompletableFuture<Pending> begin(String token, String name, String seed, String password,
                                             Long existingId, String existingCode) {
        try {
            ObjectNode body = beginBody(name, seed, password, existingId, existingCode);
            return post(token, BASE, body).thenApply(response -> {
                requireStatus(response.statusCode(), 201);
                return parsePending(response.body());
            });
        } catch (RuntimeException error) { return CompletableFuture.failedFuture(error); }
    }

    public CompletableFuture<Void> confirm(String token, Pending pending, String code) {
        try {
            if (!pending.expiresAt().isAfter(Instant.now())) throw new EnrollmentException("Enrollment expired. Start again.");
            if (code == null || !code.matches("[0-9]{6}")) throw new EnrollmentException("Enter exactly six digits.");
            return post(token, URI.create(BASE + "/" + pending.deviceId() + "/confirm"),
                    JSON.createObjectNode().put("code", code)).thenApply(response -> {
                requireStatus(response.statusCode(), 200);
                validateConfirmation(response.body(), pending.deviceId());
                return null;
            });
        } catch (RuntimeException error) { return CompletableFuture.failedFuture(error); }
    }

    private CompletableFuture<HttpResponse<String>> post(String token, URI uri, ObjectNode body) {
        if (token == null || token.isBlank()) throw new EnrollmentException("Log in again before enrolling.");
        HttpRequest request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(20))
                .header("Authorization", "Bearer " + token).header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString())).build();
        return client.sendAsync(request, HttpResponse.BodyHandlers.ofString());
    }

    static ObjectNode beginBody(String name, String seed, String password, Long existingId, String existingCode) {
        if (name == null || name.isBlank() || name.length() > 100)
            throw new EnrollmentException("Device name must contain 1 to 100 characters.");
        if (seed == null || !seed.matches("[A-Z2-7]{32}")) throw new EnrollmentException("Read a valid secret from the ESP32 first.");
        if (password == null || password.isEmpty() || password.length() > 1024)
            throw new EnrollmentException("Enter your current password.");
        if (existingId != null && (existingId < 1 || existingCode == null || !existingCode.matches("[0-9]{6}")))
            throw new EnrollmentException("Enter the existing device ID and its six-digit code.");
        ObjectNode body = JSON.createObjectNode().put("displayName", name.strip())
                .put("secretBase32", seed).put("password", password);
        if (existingId == null) { body.putNull("existingDeviceId"); body.putNull("existingCode"); }
        else { body.put("existingDeviceId", existingId); body.put("existingCode", existingCode); }
        return body;
    }

    static Pending parsePending(String body) {
        try {
            JsonNode json = JSON.readTree(body);
            long id = positiveId(json);
            String name = json.path("displayName").asText("");
            Instant expiry = Instant.parse(json.path("expiresAt").asText(""));
            if (name.isBlank() || !expiry.isAfter(Instant.now())) throw new IllegalArgumentException();
            return new Pending(id, name, expiry);
        } catch (Exception ignored) { throw new EnrollmentException("Invalid enrollment response. Start again; no activation was confirmed."); }
    }

    static void validateConfirmation(String body, long expectedId) {
        try {
            JsonNode json = JSON.readTree(body);
            if (positiveId(json) != expectedId) throw new IllegalArgumentException();
            Instant.parse(json.path("confirmedAt").asText(""));
        } catch (Exception ignored) {
            throw new EnrollmentException("Could not verify activation response. MFA may be enabled: try logging in with your ESP32.");
        }
    }

    private static long positiveId(JsonNode json) {
        JsonNode id = json.path("deviceId");
        if (!id.isIntegralNumber() || !id.canConvertToLong() || id.longValue() < 1) throw new IllegalArgumentException();
        return id.longValue();
    }

    static void requireStatus(int actual, int expected) {
        if (actual == expected) return;
        throw new EnrollmentException(switch (actual) {
            case 400 -> "Enrollment rejected. Check your password or authenticator code and input fields.";
            case 401 -> "Your session expired. Log out and sign in again.";
            case 403 -> "Existing authenticator authorization is not valid.";
            case 404 -> "Enrollment not found. Start again.";
            case 409 -> "Enrollment is no longer pending. It may already be active; try signing in with your ESP32.";
            case 410 -> "Enrollment expired. Start again.";
            case 429 -> "Too many attempts. Wait before trying again.";
            case 503 -> "Backend enrollment is unavailable. Check TOTP_ENROLLMENT_API_ENABLED and server configuration.";
            default -> "Enrollment request failed (HTTP " + actual + "). If confirming, activation may have completed; try logging in.";
        });
    }

    public static final class EnrollmentException extends RuntimeException {
        public EnrollmentException(String message) { super(message); }
    }
}
