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

    public static native boolean createStoredMlKem1024Keypair();

    public static native boolean verifyStoredMlKem1024Keypair();

    public static native boolean testStoredMlKemDekEnvelope();

    public static native boolean encryptSelectedFile(String inputPath);

    public static native boolean decryptSelectedFile(String inputPath);

    public static native boolean decryptSelectedFileTo(
            String inputPath,
            String outputPath,
            boolean overwrite
    );

    public static native int getFileCryptoProgress();
}