package kakha.kudava.filedrivespring.dto.lockbox;

import java.util.Objects;
import java.util.UUID;

public record LockboxStatusResponse(
        LockboxStatus lockboxStatus,
        DeviceStatus deviceStatus,
        UUID deviceId
) {
    public LockboxStatusResponse {
        Objects.requireNonNull(
                lockboxStatus,
                "lockboxStatus"
        );

        Objects.requireNonNull(
                deviceStatus,
                "deviceStatus"
        );

        Objects.requireNonNull(
                deviceId,
                "deviceId"
        );
    }

    public enum LockboxStatus {
        NOT_ENABLED,
        ENABLED,
        SUSPENDED
    }

    public enum DeviceStatus {
        NOT_REGISTERED,
        PENDING,
        ACTIVE,
        REVOKED
    }
}