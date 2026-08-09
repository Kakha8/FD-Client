package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import kakha.kudava.fdclient.crypto.NativeCryptoBridge;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Objects;
import java.util.UUID;

public final class CseEncryptionService {

    private static final ObjectMapper JSON = new ObjectMapper();

    public V3Artifacts encrypt(Path inputFile) {
        Objects.requireNonNull(inputFile, "inputFile");
        Path input = inputFile.toAbsolutePath().normalize();
        if (!Files.isRegularFile(input)) {
            throw new CseEncryptionException("The selected path is not a regular file.");
        }

        try {
            BasicFileAttributes attributes = Files.readAttributes(input, BasicFileAttributes.class);
            String mimeType = Files.probeContentType(input);
            if (mimeType == null || mimeType.isBlank()) {
                mimeType = "application/octet-stream";
            }
            UUID deviceId = LockboxDeviceIdentity.loadOrCreate();
            String response = NativeCryptoBridge.encryptFileV3(
                    input.toString(), input.getParent().toString(),
                    input.getFileName().toString(), mimeType, uuidBytes(deviceId),
                    attributes.creationTime().toMillis(), attributes.lastModifiedTime().toMillis()
            );
            return validateResponse(response, input.getParent());
        } catch (CseEncryptionException e) {
            throw e;
        } catch (Exception e) {
            throw new CseEncryptionException("CSEMLK03 file encryption failed.", e);
        }
    }

    public double progress() {
        return Math.max(0, Math.min(NativeCryptoBridge.getFileCryptoProgress(), 100)) / 100.0;
    }

    private V3Artifacts validateResponse(String json, Path expectedDirectory) throws IOException {
        if (json == null || json.isBlank()) {
            throw new CseEncryptionException("Native encryption returned no artifact descriptor.");
        }
        JsonNode root = JSON.readTree(json);
        UUID id = UUID.fromString(requiredText(root, "clientFileId"));
        Path container = validatedArtifact(root, "containerPath", expectedDirectory, id, ".fdcse");
        Path manifest = validatedArtifact(root, "manifestPath", expectedDirectory, id, ".fdmanifest");
        Path signature = validatedArtifact(root, "signaturePath", expectedDirectory, id, ".fdsig");
        long declaredSize = root.path("containerSize").asLong(-1);
        if (declaredSize < 0 || Files.size(container) != declaredSize) {
            throw new CseEncryptionException("Encrypted container size does not match its descriptor.");
        }
        return new V3Artifacts(id, container, manifest, signature,
                requiredHex(root, "containerHash", 128), declaredSize,
                requiredHex(root, "encryptionKeyId", 64),
                requiredHex(root, "signingKeyId", 64),
                root.path("revision").asLong(-1));
    }

    private Path validatedArtifact(JsonNode root, String field, Path directory,
                                   UUID id, String extension) {
        Path path = Path.of(requiredText(root, field)).toAbsolutePath().normalize();
        Path expected = directory.toAbsolutePath().normalize();
        if (!expected.equals(path.getParent()) ||
                !path.getFileName().toString().equals(id + extension) || !Files.isRegularFile(path)) {
            throw new CseEncryptionException("Native encryption returned an invalid " + field + ".");
        }
        return path;
    }

    private static String requiredText(JsonNode root, String field) {
        String value = root.path(field).asText("");
        if (value.isBlank()) throw new CseEncryptionException("Missing native result field: " + field);
        return value;
    }

    private static String requiredHex(JsonNode root, String field, int length) {
        String value = requiredText(root, field);
        if (value.length() != length || !value.matches("[0-9a-f]+")) {
            throw new CseEncryptionException("Invalid native result field: " + field);
        }
        return value;
    }

    private static byte[] uuidBytes(UUID uuid) {
        return ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
                .putLong(uuid.getMostSignificantBits()).putLong(uuid.getLeastSignificantBits()).array();
    }

    public record V3Artifacts(UUID clientFileId, Path containerPath, Path manifestPath,
                              Path signaturePath, String containerHash, long containerSize,
                              String encryptionKeyId, String signingKeyId, long revision) {}

    public static final class CseEncryptionException extends RuntimeException {
        public CseEncryptionException(String message) { super(message); }
        public CseEncryptionException(String message, Throwable cause) { super(message, cause); }
    }
}
