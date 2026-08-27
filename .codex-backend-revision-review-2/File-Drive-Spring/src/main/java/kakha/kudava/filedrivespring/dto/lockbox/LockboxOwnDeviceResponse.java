package kakha.kudava.filedrivespring.dto.lockbox;

import java.util.List;
import java.time.Instant;
import java.util.UUID;

public record LockboxOwnDeviceResponse(
        UUID deviceId,
        String deviceName,
        String deviceStatus,
        Instant registeredAt,
        Instant lastSeenAt,
        List<LockboxOwnDeviceKeyResponse> encryptionKeys
) {
    public LockboxOwnDeviceResponse {
        encryptionKeys = encryptionKeys == null ? List.of() : List.copyOf(encryptionKeys);
    }

    public LockboxOwnDeviceResponse(
            UUID deviceId,
            String deviceName,
            String deviceStatus,
            List<LockboxOwnDeviceKeyResponse> encryptionKeys
    ) {
        this(deviceId, deviceName, deviceStatus, null, null, encryptionKeys);
    }
}
