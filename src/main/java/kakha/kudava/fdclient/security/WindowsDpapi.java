package kakha.kudava.fdclient.security;

import com.sun.jna.Platform;
import com.sun.jna.platform.win32.Crypt32Util;
import com.sun.jna.platform.win32.WinCrypt;

import java.util.Objects;

public final class WindowsDpapi {

    private static final int FLAGS =
            WinCrypt.CRYPTPROTECT_UI_FORBIDDEN;

    public byte[] protect(byte[] plaintext) {
        requireWindows();
        Objects.requireNonNull(plaintext, "plaintext");

        return Crypt32Util.cryptProtectData(
                plaintext,
                FLAGS
        );
    }

    public byte[] unprotect(byte[] protectedData) {
        requireWindows();
        Objects.requireNonNull(protectedData, "protectedData");

        return Crypt32Util.cryptUnprotectData(
                protectedData,
                FLAGS
        );
    }

    private static void requireWindows() {
        if (!Platform.isWindows()) {
            throw new UnsupportedOperationException(
                    "DPAPI storage is only supported on Windows."
            );
        }
    }
}