package kakha.kudava.fdclient.crypto;

import java.nio.file.Files;
import java.nio.file.Path;

public final class NativeCryptoBridge {

    static {
        String configuredPath =
                System.getProperty("fdclient.native.dll");

        if (configuredPath == null || configuredPath.isBlank()) {
            throw new IllegalStateException(
                    "Missing VM option: -Dfdclient.native.dll=<path-to-native_rust.dll>"
            );
        }

        Path dllPath = Path.of(configuredPath)
                .toAbsolutePath()
                .normalize();

        if (!Files.isRegularFile(dllPath)) {
            throw new IllegalStateException(
                    "Native Rust DLL does not exist: " + dllPath
            );
        }

        System.out.println("Loading native DLL: " + dllPath);
        System.load(dllPath.toString());
    }

    private NativeCryptoBridge() {
    }

    public static native void setAccountId(long accountId);

    public static native void clearAccountId();

    public static native boolean createStoredMlKem1024Keypair();

    public static native boolean verifyStoredMlKem1024Keypair();

    public static native boolean testStoredMlKemDekEnvelope();

    public static native byte[] getStoredMlKem1024PublicKey();

    public static native byte[] getStoredMlDsa87PublicKey();

    public static native byte[] getStoredMlDsa87KeyId();

    public static native byte[] signWithStoredMlDsa87(byte[] message);

    public static native byte[] createRecipientShareEnvelopeV1(
            String containerPath,
            String manifestPath,
            String signaturePath,
            byte[] ownerPublicUuid,
            byte[] recipientPublicUuid,
            byte[] recipientMlKemPublicKey,
            long expiresAtUnixSeconds
    );

    public static native boolean encryptSelectedFile(String inputPath);

    public static native String encryptFileV3(
            String inputPath,
            String outputDirectory,
            String originalFileName,
            String mimeType,
            byte[] deviceId,
            long createdAtUnixMillis,
            long modifiedAtUnixMillis
    );

    public static native String decryptPrivateMetadataV3(
            byte[] manifest,
            byte[] signature,
            byte[] encryptedHeader
    );

    public static native boolean decryptSelectedFile(String inputPath);

    public static native boolean decryptSelectedFileTo(
            String inputPath,
            String outputPath,
            boolean overwrite
    );

    public static native int getFileCryptoProgress();
}
