package kakha.kudava.fdclient.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.Objects;
import java.util.Optional;

public final class DpapiRefreshTokenStore
        implements RefreshTokenStore {

    private final Path tokenFile;
    private final WindowsDpapi dpapi;

    public DpapiRefreshTokenStore() {
        this(defaultTokenFile(), new WindowsDpapi());
    }

    public DpapiRefreshTokenStore(
            Path tokenFile,
            WindowsDpapi dpapi
    ) {
        this.tokenFile = Objects.requireNonNull(
                tokenFile,
                "tokenFile"
        );
        this.dpapi = Objects.requireNonNull(dpapi, "dpapi");
    }

    @Override
    public void save(String refreshToken) {
        Objects.requireNonNull(refreshToken, "refreshToken");

        if (refreshToken.isBlank()) {
            throw new IllegalArgumentException(
                    "Refresh token must not be blank."
            );
        }

        byte[] plaintext =
                refreshToken.getBytes(StandardCharsets.UTF_8);

        try {
            byte[] protectedData = dpapi.protect(plaintext);
            writeAtomically(protectedData);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    @Override
    public Optional<String> load() {
        if (Files.notExists(tokenFile)) {
            return Optional.empty();
        }

        byte[] plaintext = null;

        try {
            byte[] protectedData = Files.readAllBytes(tokenFile);
            plaintext = dpapi.unprotect(protectedData);

            return Optional.of(
                    new String(plaintext, StandardCharsets.UTF_8)
            );
        } catch (IOException exception) {
            throw new TokenStorageException(
                    "Could not read the saved refresh token.",
                    exception
            );
        } finally {
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    @Override
    public void delete() {
        try {
            Files.deleteIfExists(tokenFile);
        } catch (IOException exception) {
            throw new TokenStorageException(
                    "Could not delete the saved refresh token.",
                    exception
            );
        }
    }

    public Path tokenFile() {
        return tokenFile;
    }

    private void writeAtomically(byte[] protectedData) {
        Path parent = tokenFile.getParent();
        Path temporaryFile = tokenFile.resolveSibling(
                tokenFile.getFileName() + ".tmp"
        );

        try {
            Files.createDirectories(parent);
            Files.write(temporaryFile, protectedData);

            try {
                Files.move(
                        temporaryFile,
                        tokenFile,
                        StandardCopyOption.REPLACE_EXISTING,
                        StandardCopyOption.ATOMIC_MOVE
                );
            } catch (AtomicMoveNotSupportedException exception) {
                Files.move(
                        temporaryFile,
                        tokenFile,
                        StandardCopyOption.REPLACE_EXISTING
                );
            }
        } catch (IOException exception) {
            try {
                Files.deleteIfExists(temporaryFile);
            } catch (IOException ignored) {
                // Preserve the original exception.
            }

            throw new TokenStorageException(
                    "Could not save the refresh token.",
                    exception
            );
        }
    }

    private static Path defaultTokenFile() {
        String localAppData = System.getenv("LOCALAPPDATA");

        Path applicationDirectory;

        if (localAppData != null && !localAppData.isBlank()) {
            applicationDirectory = Path.of(
                    localAppData,
                    "FD-Client"
            );
        } else {
            applicationDirectory = Path.of(
                    System.getProperty("user.home"),
                    ".fd-client"
            );
        }

        return applicationDirectory
                .resolve("auth")
                .resolve("refresh-token.dpapi");
    }

    public static final class TokenStorageException
            extends RuntimeException {

        public TokenStorageException(
                String message,
                Throwable cause
        ) {
            super(message, cause);
        }
    }
}