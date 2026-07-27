package kakha.kudava.fdclient.service;

import kakha.kudava.fdclient.crypto.NativeCryptoBridge;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;

public final class CseEncryptionService {

    public Path encrypt(Path inputFile) {
        Objects.requireNonNull(inputFile, "inputFile");

        if (!Files.isRegularFile(inputFile)) {
            throw new CseEncryptionException(
                    "The selected path is not a regular file."
            );
        }

        Path outputFile = encryptedOutputPath(inputFile);

        if (Files.exists(outputFile)) {
            throw new CseEncryptionException(
                    "The encrypted output already exists:\n"
                            + outputFile
            );
        }

        ensureEncryptionKeyExists();

        boolean successful =
                NativeCryptoBridge.encryptSelectedFile(
                        inputFile.toAbsolutePath().toString()
                );

        if (!successful) {
            throw new CseEncryptionException(
                    "Native file encryption failed."
            );
        }

        if (!Files.isRegularFile(outputFile)) {
            throw new CseEncryptionException(
                    "Encryption reported success, but the "
                            + "encrypted output was not created."
            );
        }

        return outputFile;
    }

    public double progress() {
        int nativePercent =
                NativeCryptoBridge.getFileCryptoProgress();

        int safePercent = Math.max(
                0,
                Math.min(nativePercent, 100)
        );

        return safePercent / 100.0;
    }

    private void ensureEncryptionKeyExists() {
        if (NativeCryptoBridge
                .verifyStoredMlKem1024Keypair()) {
            return;
        }

        boolean created =
                NativeCryptoBridge
                        .createStoredMlKem1024Keypair();

        if (!created
                || !NativeCryptoBridge
                .verifyStoredMlKem1024Keypair()) {

            throw new CseEncryptionException(
                    "Could not create or load the local "
                            + "ML-KEM encryption key."
            );
        }
    }

    private Path encryptedOutputPath(Path inputFile) {
        return inputFile.resolveSibling(
                inputFile.getFileName() + ".cseml"
        );
    }

    public static final class CseEncryptionException
            extends RuntimeException {

        public CseEncryptionException(String message) {
            super(message);
        }
    }
}