package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import kakha.kudava.fdclient.crypto.NativeCryptoBridge;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public final class LockboxMetadataService {

    private static final URI LIST_URI = URI.create(
            "https://localhost:8443/api/lockbox/files/private-metadata"
    );
    private static final int MAX_MANIFEST = 1_024;
    private static final int MAX_SIGNATURE = 16 * 1_024;
    private static final int MAX_HEADER = 1024 * 1024;

    private final ObjectMapper json = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15)).build();

    public CompletableFuture<List<PrivateFile>> list(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException("No authenticated session is available."));
        }
        HttpRequest request = HttpRequest.newBuilder(LIST_URI)
                .timeout(Duration.ofMinutes(2))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET().build();
        return http.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                .thenApply(this::parseResponse);
    }

    private List<PrivateFile> parseResponse(HttpResponse<String> response) {
        if (response.statusCode() == 401 || response.statusCode() == 403) {
            throw new IllegalStateException("Your session is no longer authorized.");
        }
        if (response.statusCode() != 200) {
            throw new IllegalStateException("Lockbox file listing failed with HTTP "
                    + response.statusCode() + ".");
        }
        try {
            JsonNode files = json.readTree(response.body()).path("files");
            if (!files.isArray()) throw new IllegalStateException("Invalid Lockbox list response.");
            List<PrivateFile> result = new ArrayList<>(files.size());
            for (JsonNode item : files) result.add(decryptItem(item));
            return List.copyOf(result);
        } catch (RuntimeException error) {
            throw error;
        } catch (Exception error) {
            throw new IllegalStateException("Could not read the private Lockbox file list.", error);
        }
    }

    private PrivateFile decryptItem(JsonNode item) throws Exception {
        long id = item.path("id").asLong(-1);
        UUID clientFileId = UUID.fromString(item.path("clientFileId").asText());
        long revision = item.path("revision").asLong(-1);
        byte[] manifest = decode(item, "manifest", MAX_MANIFEST);
        byte[] signature = decode(item, "signature", MAX_SIGNATURE);
        byte[] header = decode(item, "encryptedHeader", MAX_HEADER);
        String decrypted = NativeCryptoBridge.decryptPrivateMetadataV3(
                manifest, signature, header);
        JsonNode metadata = json.readTree(decrypted);
        long decryptedRevision = metadata.path("revision").asLong(-1);
        UUID decryptedFileId = UUID.fromString(metadata.path("clientFileId").asText());
        if (id < 1 || revision < 1 || revision != decryptedRevision
                || !clientFileId.equals(decryptedFileId)) {
            throw new IllegalStateException("Private metadata does not match its server record.");
        }
        return new PrivateFile(
                id, clientFileId, revision,
                requiredText(metadata, "filename"), requiredText(metadata, "mimeType"),
                metadata.path("exactPlaintextSize").asLong(-1),
                Instant.ofEpochMilli(metadata.path("createdAtUnixMillis").asLong()),
                Instant.ofEpochMilli(metadata.path("modifiedAtUnixMillis").asLong())
        );
    }

    private byte[] decode(JsonNode item, String field, int maximum) {
        byte[] bytes = Base64.getDecoder().decode(requiredText(item, field));
        if (bytes.length == 0 || bytes.length > maximum) {
            throw new IllegalStateException("Invalid Lockbox " + field + " length.");
        }
        return bytes;
    }

    private String requiredText(JsonNode node, String field) {
        String value = node.path(field).asText("");
        if (value.isBlank()) throw new IllegalStateException("Missing Lockbox field: " + field);
        return value;
    }

    public record PrivateFile(long id, UUID clientFileId, long revision, String filename,
                              String mimeType, long plaintextSize,
                              Instant createdAt, Instant modifiedAt) {}
}
