package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import kakha.kudava.fdclient.crypto.NativeCryptoBridge;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

public final class LockboxReceivedShareService {
    private static final URI LIST_URI = URI.create(
            BackendConfig.uri("/api/lockbox/shares/received").toString());
    private static final ObjectMapper JSON = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15)).build();

    public CompletableFuture<List<LockboxMetadataService.PrivateFile>> list(
            String accessToken,
            UUID recipientPublicUuid,
            UUID deviceId
    ) {
        if (accessToken == null || accessToken.isBlank()
                || recipientPublicUuid == null || deviceId == null) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException("No authenticated Lockbox account is available."));
        }
        URI requestUri = URI.create(LIST_URI + "?deviceId=" + deviceId);
        HttpRequest request = HttpRequest.newBuilder(requestUri)
                .timeout(Duration.ofMinutes(2))
                .header("Authorization", "Bearer " + accessToken)
                .header("Accept", "application/json")
                .GET().build();
        return http.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                .handle((response, error) -> {
                    if (error != null) throw new CompletionException(error);
                    if (response.statusCode() == 401 || response.statusCode() == 403) {
                        throw new LockboxMetadataService.UnauthorizedException(
                                "Your session is no longer authorized.");
                    }
                    if (response.statusCode() != 200) {
                        throw new IllegalStateException(
                                "Received Lockbox share listing failed with HTTP "
                                        + response.statusCode() + ".");
                    }
                    return parse(response.body(), recipientPublicUuid);
                });
    }

    private List<LockboxMetadataService.PrivateFile> parse(
            String body,
            UUID recipientPublicUuid
    ) {
        try {
            JsonNode shares = JSON.readTree(body).path("shares");
            if (!shares.isArray()) {
                throw new IllegalStateException("Invalid received-share list response.");
            }
            List<LockboxMetadataService.PrivateFile> result = new ArrayList<>(shares.size());
            for (JsonNode item : shares) result.add(decrypt(item, recipientPublicUuid));
            return List.copyOf(result);
        } catch (RuntimeException error) {
            throw error;
        } catch (Exception error) {
            throw new IllegalStateException("Could not verify received Lockbox shares.", error);
        }
    }

    private LockboxMetadataService.PrivateFile decrypt(
            JsonNode item,
            UUID recipientPublicUuid
    ) throws Exception {
        UUID shareId = UUID.fromString(requiredText(item, "shareId"));
        long fileId = item.path("fileId").asLong(-1);
        UUID clientFileId = UUID.fromString(requiredText(item, "clientFileId"));
        long revision = item.path("revision").asLong(-1);
        String owner = requiredText(item, "ownerUsername");
        if (fileId < 1 || revision < 1 || !"READ".equals(requiredText(item, "permission"))) {
            throw new IllegalStateException("Invalid received-share identity fields.");
        }

        ReceivedShareArtifacts artifacts = new ReceivedShareArtifacts(
                exact(item, "recipientEnvelope", 1_858),
                exact(item, "ownerShareSignature", 4_627),
                exact(item, "ownerSigningKeyId", 32),
                exact(item, "ownerSigningPublicKey", 2_592),
                exact(item, "manifest", 264),
                exact(item, "fileSignature", 4_675),
                bounded(item, "encryptedHeader", 32, 1024 * 1024),
                recipientPublicUuid
        );
        String decrypted = NativeCryptoBridge.decryptReceivedShareMetadataV1(
                artifacts.recipientEnvelope(), artifacts.ownerShareSignature(),
                artifacts.ownerSigningKeyId(), artifacts.ownerSigningPublicKey(),
                artifacts.manifest(), artifacts.fileSignature(), artifacts.encryptedHeader(),
                uuidBytes(shareId), uuidBytes(recipientPublicUuid), uuidBytes(clientFileId), revision);
        JsonNode metadata = JSON.readTree(decrypted);
        if (!clientFileId.equals(UUID.fromString(requiredText(metadata, "clientFileId")))
                || revision != metadata.path("revision").asLong(-1)) {
            throw new IllegalStateException("Decrypted share metadata does not match the share.");
        }
        return new LockboxMetadataService.PrivateFile(
                fileId, clientFileId, revision,
                requiredText(metadata, "filename"), requiredText(metadata, "mimeType"),
                metadata.path("exactPlaintextSize").asLong(-1),
                Instant.ofEpochMilli(metadata.path("createdAtUnixMillis").asLong()),
                Instant.ofEpochMilli(metadata.path("modifiedAtUnixMillis").asLong()),
                LockboxMetadataService.Location.WEB, null,
                LockboxMetadataService.AccessKind.SHARED_WITH_ME,
                shareId, owner, artifacts);
    }

    private byte[] exact(JsonNode item, String field, int length) {
        byte[] value = decode(item, field);
        if (value.length != length) throw new IllegalStateException("Invalid " + field + " length.");
        return value;
    }

    private byte[] bounded(JsonNode item, String field, int minimum, int maximum) {
        byte[] value = decode(item, field);
        if (value.length < minimum || value.length > maximum) {
            throw new IllegalStateException("Invalid " + field + " length.");
        }
        return value;
    }

    private byte[] decode(JsonNode item, String field) {
        try {
            return Base64.getDecoder().decode(requiredText(item, field));
        } catch (IllegalArgumentException error) {
            throw new IllegalStateException("Invalid Base64 in received share: " + field, error);
        }
    }

    private String requiredText(JsonNode node, String field) {
        String value = node.path(field).asText("");
        if (value.isBlank()) throw new IllegalStateException("Missing received-share field: " + field);
        return value;
    }

    static byte[] uuidBytes(UUID uuid) {
        return ByteBuffer.allocate(16)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits())
                .array();
    }

    public record ReceivedShareArtifacts(
            byte[] recipientEnvelope,
            byte[] ownerShareSignature,
            byte[] ownerSigningKeyId,
            byte[] ownerSigningPublicKey,
            byte[] manifest,
            byte[] fileSignature,
            byte[] encryptedHeader,
            UUID recipientPublicUuid
    ) {}
}
