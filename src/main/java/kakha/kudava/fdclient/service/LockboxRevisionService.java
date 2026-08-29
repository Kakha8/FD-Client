package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/** Reads the immutable revision history for an owned Lockbox file. */
public final class LockboxRevisionService {
    private static final ObjectMapper JSON = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15)).build();

    public CompletableFuture<RevisionHistory> history(long fileId, String accessToken) {
        if (fileId < 1) return CompletableFuture.failedFuture(
                new IllegalArgumentException("A valid Lockbox file is required."));
        if (accessToken == null || accessToken.isBlank()) return CompletableFuture.failedFuture(
                new IllegalStateException("No authenticated session is available."));

        HttpRequest request = HttpRequest.newBuilder(BackendConfig.uri(
                        "/api/lockbox/files/" + fileId + "/revisions"))
                .timeout(Duration.ofMinutes(2))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET().build();
        return http.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                .thenApply(response -> {
                    if (response.statusCode() == 401 || response.statusCode() == 403) {
                        throw new LockboxDownloadService.UnauthorizedException(
                                "Your session is no longer authorized.");
                    }
                    if (response.statusCode() != 200) {
                        throw new IllegalStateException("Revision history returned HTTP "
                                + response.statusCode() + ".");
                    }
                    try {
                        return parse(response.body());
                    } catch (RuntimeException error) {
                        throw error;
                    } catch (Exception error) {
                        throw new CompletionException(new IllegalStateException(
                                "The revision history response is invalid.", error));
                    }
                });
    }

    static RevisionHistory parse(String body) throws Exception {
        JsonNode root = JSON.readTree(body);
        long fileId = root.path("fileId").asLong(-1);
        UUID clientFileId = UUID.fromString(root.path("clientFileId").asText(""));
        long currentRevision = root.path("currentRevision").asLong(-1);
        JsonNode values = root.path("revisions");
        if (fileId < 1 || currentRevision < 1 || !values.isArray()) {
            throw new IllegalStateException("Invalid revision history identity.");
        }
        List<Revision> revisions = new ArrayList<>(values.size());
        for (JsonNode value : values) {
            Revision revision = new Revision(
                    value.path("revision").asLong(-1),
                    value.path("containerSize").asLong(-1),
                    requiredText(value, "containerHash"),
                    Instant.parse(requiredText(value, "createdAt")),
                    value.path("current").asBoolean(false));
            if (revision.revision() < 1 || revision.containerSize() < 1
                    || revision.containerHash().length() != 128) {
                throw new IllegalStateException("Invalid revision history entry.");
            }
            revisions.add(revision);
        }
        long currentCount = revisions.stream().filter(Revision::current).count();
        if (revisions.isEmpty() || currentCount != 1
                || revisions.stream().noneMatch(r -> r.revision() == currentRevision && r.current())) {
            throw new IllegalStateException("Revision history has no unique current revision.");
        }
        return new RevisionHistory(fileId, clientFileId, currentRevision, revisions);
    }

    private static String requiredText(JsonNode node, String field) {
        String value = node.path(field).asText("");
        if (value.isBlank()) throw new IllegalStateException("Missing field: " + field);
        return value;
    }

    public record RevisionHistory(long fileId, UUID clientFileId, long currentRevision,
                                  List<Revision> revisions) {
        public RevisionHistory {
            revisions = List.copyOf(revisions);
        }
    }

    public record Revision(long revision, long containerSize, String containerHash,
                           Instant createdAt, boolean current) {
        @Override public String toString() {
            return "Version " + revision + (current ? " (current)" : "")
                    + " — " + createdAt;
        }
    }
}
