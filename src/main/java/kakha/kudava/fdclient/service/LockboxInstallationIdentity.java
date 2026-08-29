package kakha.kudava.fdclient.service;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

/** Maintains the app-installation identity and derives account-scoped handles. */
public final class LockboxInstallationIdentity {

    private static final byte[] HANDLE_DOMAIN =
            "FD-INSTALLATION-HANDLE-V1\0".getBytes(StandardCharsets.US_ASCII);
    private static final String FILE_NAME = "installation-id";

    private LockboxInstallationIdentity() {}

    public static synchronized UUID loadOrCreate() {
        return loadOrCreate(installationPath());
    }

    static UUID loadOrCreate(Path path) {
        Objects.requireNonNull(path, "path");
        if (Files.exists(path)) {
            return read(path);
        }

        UUID created = UUID.randomUUID();
        try {
            Files.createDirectories(path.getParent());
            Files.writeString(
                    path,
                    created.toString(),
                    StandardCharsets.US_ASCII,
                    StandardOpenOption.CREATE_NEW,
                    StandardOpenOption.WRITE
            );
            return created;
        } catch (java.nio.file.FileAlreadyExistsException ignored) {
            return read(path);
        } catch (IOException exception) {
            throw new IllegalStateException(
                    "Could not persist the File Drive installation ID.",
                    exception
            );
        }
    }

    public static String deriveHandle(UUID installationId, UUID userPublicUuid) {
        Objects.requireNonNull(installationId, "installationId");
        Objects.requireNonNull(userPublicUuid, "userPublicUuid");

        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA3-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA3-256 is unavailable.", exception);
        }
        digest.update(HANDLE_DOMAIN);
        digest.update(uuidBytes(installationId));
        digest.update(uuidBytes(userPublicUuid));
        return Base64.getEncoder().encodeToString(digest.digest());
    }

    static byte[] uuidBytes(UUID value) {
        return ByteBuffer.allocate(16)
                .order(ByteOrder.BIG_ENDIAN)
                .putLong(value.getMostSignificantBits())
                .putLong(value.getLeastSignificantBits())
                .array();
    }

    private static UUID read(Path path) {
        try {
            return UUID.fromString(
                    Files.readString(path, StandardCharsets.US_ASCII).trim()
            );
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "The stored File Drive installation ID is invalid.",
                    exception
            );
        }
    }

    private static Path installationPath() {
        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData == null || localAppData.isBlank()) {
            throw new IllegalStateException("LOCALAPPDATA is unavailable.");
        }
        return Path.of(localAppData, "FileDrive", FILE_NAME)
                .toAbsolutePath()
                .normalize();
    }
}
