package kakha.kudava.fdclient.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.UUID;

/** Persists the non-secret Lockbox device UUID across client restarts and retries. */
public final class LockboxDeviceIdentity {

    private static final String FILE_NAME = "lockbox-device-id";

    private LockboxDeviceIdentity() {}

    public static synchronized UUID loadOrCreate() {
        Path path = identityPath();
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
        } catch (IOException e) {
            throw new IllegalStateException("Could not persist the Lockbox device ID.", e);
        }
    }

    private static UUID read(Path path) {
        try {
            return UUID.fromString(Files.readString(path, StandardCharsets.US_ASCII).trim());
        } catch (Exception e) {
            throw new IllegalStateException("The stored Lockbox device ID is invalid.", e);
        }
    }

    private static Path identityPath() {
        return LockboxAccountContext.accountDirectory()
                .resolve("device")
                .resolve(FILE_NAME);
    }
}
