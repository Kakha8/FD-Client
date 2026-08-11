package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import kakha.kudava.fdclient.crypto.NativeCryptoBridge;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

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
                .handle((response, error) -> {
                    List<PrivateFile> local = localFiles();
                    if (error != null) {
                        if (!local.isEmpty()) return local;
                        throw new CompletionException(error);
                    }
                    return merge(local, parseResponse(response));
                });
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
                Instant.ofEpochMilli(metadata.path("modifiedAtUnixMillis").asLong()),
                Location.WEB, null
        );
    }

    private List<PrivateFile> localFiles() {
        Path directory = new CseEncryptionService().artifactDirectory();
        List<PrivateFile> result = new ArrayList<>();
        try (var files = Files.list(directory)) {
            files.filter(path -> path.getFileName().toString().endsWith(".fdmanifest"))
                    .forEach(manifest -> {
                        try {
                            String name = manifest.getFileName().toString();
                            UUID id = UUID.fromString(name.substring(0, name.length() - ".fdmanifest".length()));
                            Path signature = directory.resolve(id + ".fdsig");
                            Path container = directory.resolve(id + ".fdcse");
                            if (!Files.isRegularFile(signature) || !Files.isRegularFile(container)) return;
                            byte[] manifestBytes = boundedRead(manifest, MAX_MANIFEST);
                            byte[] signatureBytes = boundedRead(signature, MAX_SIGNATURE);
                            byte[] header = readHeader(container);
                            JsonNode metadata = json.readTree(NativeCryptoBridge.decryptPrivateMetadataV3(
                                    manifestBytes, signatureBytes, header));
                            UUID decryptedId = UUID.fromString(requiredText(metadata, "clientFileId"));
                            if (!id.equals(decryptedId)) throw new IllegalStateException("Local UUID mismatch.");
                            result.add(new PrivateFile(
                                    null, id, metadata.path("revision").asLong(-1),
                                    requiredText(metadata, "filename"), requiredText(metadata, "mimeType"),
                                    metadata.path("exactPlaintextSize").asLong(-1),
                                    Instant.ofEpochMilli(metadata.path("createdAtUnixMillis").asLong()),
                                    Instant.ofEpochMilli(metadata.path("modifiedAtUnixMillis").asLong()),
                                    Location.LOCAL, container));
                        } catch (Exception error) {
                            System.err.println("Ignoring invalid local Lockbox artifact set: " + error.getMessage());
                        }
                    });
        } catch (Exception error) {
            throw new IllegalStateException("Could not scan local Lockbox artifacts.", error);
        }
        return result;
    }

    private List<PrivateFile> merge(List<PrivateFile> local, List<PrivateFile> web) {
        Map<UUID, PrivateFile> merged = new LinkedHashMap<>();
        for (PrivateFile file : local) merged.put(file.clientFileId(), file);
        for (PrivateFile remote : web) {
            PrivateFile localFile = merged.get(remote.clientFileId());
            if (localFile == null) {
                merged.put(remote.clientFileId(), remote);
            } else {
                merged.put(remote.clientFileId(), new PrivateFile(
                        remote.serverId(), remote.clientFileId(), remote.revision(),
                        remote.filename(), remote.mimeType(), remote.plaintextSize(),
                        remote.createdAt(), remote.modifiedAt(), Location.BOTH,
                        localFile.localContainerPath()));
            }
        }
        return merged.values().stream()
                .sorted((a, b) -> b.modifiedAt().compareTo(a.modifiedAt())).toList();
    }

    private byte[] boundedRead(Path path, int maximum) throws Exception {
        long size = Files.size(path);
        if (size < 1 || size > maximum) throw new IllegalStateException("Invalid artifact size.");
        return Files.readAllBytes(path);
    }

    private byte[] readHeader(Path container) throws Exception {
        byte[] preamble;
        try (var input = Files.newInputStream(container)) {
            preamble = input.readNBytes(32);
            if (preamble.length != 32) throw new IllegalStateException("Truncated header.");
            long length = Integer.toUnsignedLong(ByteBuffer.wrap(preamble, 12, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt());
            if (length < 32 || length > MAX_HEADER) throw new IllegalStateException("Invalid header length.");
            byte[] header = new byte[(int) length];
            System.arraycopy(preamble, 0, header, 0, 32);
            byte[] rest = input.readNBytes((int) length - 32);
            if (rest.length != length - 32) throw new IllegalStateException("Truncated header.");
            System.arraycopy(rest, 0, header, 32, rest.length);
            return header;
        }
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

    public record PrivateFile(Long serverId, UUID clientFileId, long revision, String filename,
                              String mimeType, long plaintextSize,
                              Instant createdAt, Instant modifiedAt,
                              Location location, Path localContainerPath) {}

    public enum Location {
        LOCAL("Local"), WEB("Web"), BOTH("Local + Web");
        private final String displayName;
        Location(String displayName) { this.displayName = displayName; }
        public String displayName() { return displayName; }
    }
}
