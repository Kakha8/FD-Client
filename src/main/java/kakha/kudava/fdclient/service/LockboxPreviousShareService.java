package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/** Reads active recipients of an owned, immutable revision. */
public final class LockboxPreviousShareService {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15)).build();

    public CompletableFuture<List<PreviousShare>> list(
            long fileId, long revision, String accessToken) {
        if (fileId < 1 || revision < 1) return CompletableFuture.failedFuture(
                new IllegalArgumentException("A valid Lockbox revision is required."));
        if (accessToken == null || accessToken.isBlank()) return CompletableFuture.failedFuture(
                new IllegalStateException("No authenticated session is available."));
        HttpRequest request = HttpRequest.newBuilder(BackendConfig.uri(
                        "/api/lockbox/files/" + fileId + "/revisions/"
                                + revision + "/shares"))
                .timeout(Duration.ofMinutes(2))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json").GET().build();
        return http.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                .thenApply(response -> {
                    if (response.statusCode() == 401 || response.statusCode() == 403) {
                        throw new LockboxDownloadService.UnauthorizedException(
                                "Your session is no longer authorized.");
                    }
                    if (response.statusCode() != 200) {
                        throw new IllegalStateException("Previous-share lookup returned HTTP "
                                + response.statusCode() + ".");
                    }
                    try { return parse(response.body()); }
                    catch (RuntimeException error) { throw error; }
                    catch (Exception error) {
                        throw new CompletionException(new IllegalStateException(
                                "The previous-share response is invalid.", error));
                    }
                });
    }

    static List<PreviousShare> parse(String body) throws Exception {
        JsonNode values = JSON.readTree(body).path("shares");
        if (!values.isArray()) throw new IllegalStateException("Missing shares array.");
        List<PreviousShare> result = new ArrayList<>(values.size());
        for (JsonNode value : values) {
            String username = requiredText(value, "recipientUsername");
            String device = value.path("targetDeviceId").asText("");
            UUID targetDeviceId = device.isBlank() ? null : UUID.fromString(device);
            long expiresAt = value.path("expiresAtUnixSeconds").asLong(0);
            if (expiresAt < 0) throw new IllegalStateException("Invalid share expiry.");
            result.add(new PreviousShare(username, targetDeviceId, expiresAt));
        }
        return List.copyOf(result);
    }

    private static String requiredText(JsonNode node, String field) {
        String value = node.path(field).asText("").trim();
        if (value.isBlank()) throw new IllegalStateException("Missing field: " + field);
        return value;
    }

    public record PreviousShare(String recipientUsername, UUID targetDeviceId,
                                long expiresAtUnixSeconds) {
        public boolean deviceTargeted() { return targetDeviceId != null; }
    }
}
