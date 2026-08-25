package kakha.kudava.fdclient.service;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

public record LockboxOwnDevice(
        UUID deviceId,
        String deviceName,
        List<LockboxRecipientEncryptionKey> encryptionKeys
) {
    public LockboxOwnDevice {
        deviceId = Objects.requireNonNull(deviceId, "deviceId");
        deviceName = Objects.requireNonNull(deviceName, "deviceName").trim();
        encryptionKeys = List.copyOf(Objects.requireNonNull(encryptionKeys, "encryptionKeys"));
        if (deviceName.isEmpty() || encryptionKeys.isEmpty()) {
            throw new IllegalArgumentException("An eligible target device and encryption key are required.");
        }
    }

    public LockboxRecipientEncryptionKey primaryEncryptionKey() {
        return encryptionKeys.getFirst();
    }

    @Override
    public String toString() {
        return deviceName + " (" + deviceId.toString().substring(0, 8) + ")";
    }
}
