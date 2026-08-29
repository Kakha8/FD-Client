package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import kakha.kudava.fdclient.crypto.NativeCryptoBridge;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.UUID;
import java.security.MessageDigest;

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
            Path outputDirectory = artifactDirectory();
            UUID deviceId = LockboxDeviceIdentity.loadOrCreate();
            String response = NativeCryptoBridge.encryptFileV3(
                    input.toString(), outputDirectory.toString(),
                    input.getFileName().toString(), mimeType, uuidBytes(deviceId),
                    attributes.creationTime().toMillis(), attributes.lastModifiedTime().toMillis()
            );
            return validateResponse(response, outputDirectory);
        } catch (CseEncryptionException e) {
            throw e;
        } catch (Exception e) {
            throw new CseEncryptionException("CSEMLK03 file encryption failed.", e);
        }
    }

    public V3Artifacts encryptRevision(
            Path inputFile,
            UUID clientFileId,
            long currentRevision,
            Path previousManifest,
            Instant logicalCreatedAt
    ) {
        Objects.requireNonNull(inputFile, "inputFile");
        Objects.requireNonNull(clientFileId, "clientFileId");
        Objects.requireNonNull(previousManifest, "previousManifest");
        Objects.requireNonNull(logicalCreatedAt, "logicalCreatedAt");
        if (currentRevision < 1 || currentRevision == Long.MAX_VALUE) {
            throw new CseEncryptionException("The current Lockbox revision is invalid.");
        }
        Path input = inputFile.toAbsolutePath().normalize();
        Path manifest = previousManifest.toAbsolutePath().normalize();
        if (!Files.isRegularFile(input) || !Files.isRegularFile(manifest)) {
            throw new CseEncryptionException("The replacement file or previous manifest is unavailable.");
        }

        try {
            BasicFileAttributes attributes = Files.readAttributes(input, BasicFileAttributes.class);
            String mimeType = Files.probeContentType(input);
            if (mimeType == null || mimeType.isBlank()) mimeType = "application/octet-stream";
            Path staging = Files.createTempDirectory(artifactDirectory(), ".revision-");
            byte[] previousHash = MessageDigest.getInstance("SHA3-512")
                    .digest(Files.readAllBytes(manifest));
            String response = NativeCryptoBridge.encryptFileRevisionV3(
                    input.toString(), staging.toString(), input.getFileName().toString(), mimeType,
                    uuidBytes(LockboxDeviceIdentity.loadOrCreate()), logicalCreatedAt.toEpochMilli(),
                    attributes.lastModifiedTime().toMillis(), uuidBytes(clientFileId),
                    currentRevision + 1, previousHash);
            V3Artifacts artifacts = validateResponse(response, staging);
            if (!clientFileId.equals(artifacts.clientFileId())
                    || artifacts.revision() != currentRevision + 1) {
                throw new CseEncryptionException("Native encryption returned the wrong revision identity.");
            }
            return artifacts;
        } catch (CseEncryptionException error) {
            throw error;
        } catch (Exception error) {
            throw new CseEncryptionException("CSEMLK03 revision encryption failed.", error);
        }
    }

    public double progress() {
        return Math.max(0, Math.min(NativeCryptoBridge.getFileCryptoProgress(), 100)) / 100.0;
    }

    public Path artifactDirectory() {
        Path directory = LockboxAccountContext.accountDirectory()
                .resolve("lockbox")
                .resolve("artifacts")
                .toAbsolutePath().normalize();
        try {
            Files.createDirectories(directory);
        } catch (IOException error) {
            throw new CseEncryptionException(
                    "Could not create the Lockbox artifact directory: " + directory, error);
        }
        if (!Files.isDirectory(directory)) {
            throw new CseEncryptionException(
                    "The Lockbox artifact path is not a directory: " + directory);
        }
        return directory;
    }

    public V3Artifacts loadLocalArtifacts(
            UUID clientFileId,
            Path containerPath
    ) {
        Objects.requireNonNull(clientFileId, "clientFileId");
        Objects.requireNonNull(containerPath, "containerPath");

        Path container = containerPath.toAbsolutePath().normalize();
        Path directory = artifactDirectory();
        String base = clientFileId.toString();
        Path manifest = directory.resolve(base + ".fdmanifest");
        Path signature = directory.resolve(base + ".fdsig");

        if (!directory.equals(container.getParent())
                || !container.getFileName().toString().equals(base + ".fdcse")
                || !Files.isRegularFile(container)
                || !Files.isRegularFile(manifest)
                || !Files.isRegularFile(signature)) {
            throw new CseEncryptionException("The local Lockbox artifact set is incomplete.");
        }

        try {
            byte[] bytes = Files.readAllBytes(manifest);
            if (bytes.length != 264
                    || !Arrays.equals(Arrays.copyOfRange(bytes, 0, 8),
                    "FDMAN003".getBytes(StandardCharsets.US_ASCII))
                    || !Arrays.equals(Arrays.copyOfRange(bytes, 16, 32), uuidBytes(clientFileId))) {
                throw new CseEncryptionException("The local Lockbox manifest is invalid.");
            }

            ByteBuffer manifestData = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
            long revision = manifestData.getLong(32);
            long containerSize = manifestData.getLong(40);
            if (revision < 1 || containerSize < 0 || Files.size(container) != containerSize) {
                throw new CseEncryptionException("The local container does not match its manifest.");
            }

            HexFormat hex = HexFormat.of();
            return new V3Artifacts(
                    clientFileId,
                    container,
                    manifest,
                    signature,
                    hex.formatHex(bytes, 48, 112),
                    containerSize,
                    hex.formatHex(bytes, 112, 144),
                    hex.formatHex(bytes, 144, 176),
                    revision
            );
        } catch (CseEncryptionException error) {
            throw error;
        } catch (Exception error) {
            throw new CseEncryptionException("Could not load the local Lockbox artifacts.", error);
        }
    }

    public void commitRevision(V3Artifacts staged) {
        Objects.requireNonNull(staged, "staged");
        Path destination = artifactDirectory();
        Path staging = staged.containerPath().toAbsolutePath().normalize().getParent();
        if (staging == null || !staging.getParent().equals(destination)
                || !staging.getFileName().toString().startsWith(".revision-")) {
            throw new CseEncryptionException("The staged revision directory is invalid.");
        }
        try {
            moveReplacing(staged.containerPath(), destination.resolve(staged.clientFileId() + ".fdcse"));
            moveReplacing(staged.manifestPath(), destination.resolve(staged.clientFileId() + ".fdmanifest"));
            moveReplacing(staged.signaturePath(), destination.resolve(staged.clientFileId() + ".fdsig"));
            Files.deleteIfExists(staging);
        } catch (Exception error) {
            throw new CseEncryptionException(
                    "The new revision was accepted by the server, but its local artifacts could not be installed.",
                    error);
        }
    }

    public void discardRevision(V3Artifacts staged) {
        if (staged == null || staged.containerPath() == null) return;
        Path staging = staged.containerPath().toAbsolutePath().normalize().getParent();
        Path destination = artifactDirectory();
        if (staging == null || !destination.equals(staging.getParent())
                || !staging.getFileName().toString().startsWith(".revision-")) return;
        try (var paths = Files.walk(staging)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try { Files.deleteIfExists(path); } catch (IOException ignored) {}
            });
        } catch (IOException ignored) {}
    }

    private static void moveReplacing(Path source, Path destination) throws IOException {
        try {
            Files.move(source, destination, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
            Files.move(source, destination, StandardCopyOption.REPLACE_EXISTING);
        }
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
