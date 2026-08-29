package kakha.kudava.fdclient.service;

import kakha.kudava.fdclient.crypto.NativeCryptoBridge;

import java.nio.file.Path;

public final class LockboxAccountContext {
    private static volatile Long accountId;

    private LockboxAccountContext() {}

    public static synchronized void activate(long userId) {
        if (userId < 1) throw new IllegalArgumentException("Account ID must be positive.");
        NativeCryptoBridge.setAccountId(userId);
        accountId = userId;
    }

    public static synchronized void clear() {
        NativeCryptoBridge.clearAccountId();
        accountId = null;
    }

    public static long requireAccountId() {
        Long value = accountId;
        if (value == null) throw new IllegalStateException("No active Lockbox account context.");
        return value;
    }

    public static Path accountDirectory() {
        String localAppData = System.getenv("LOCALAPPDATA");
        if (localAppData == null || localAppData.isBlank()) {
            throw new IllegalStateException("LOCALAPPDATA is unavailable.");
        }
        return Path.of(localAppData, "FileDrive", "accounts",
                Long.toString(requireAccountId())).toAbsolutePath().normalize();
    }
}
