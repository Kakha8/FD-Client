package kakha.kudava.filedrivespring.dto.lockbox;

import java.util.UUID;

public record LockboxEnrollmentCompleteResponse(
        LockboxProfileStatus lockboxStatus,
        LockboxDeviceStatus deviceStatus,
        UUID deviceId,
        String encryptionKeyId,
        String signingKeyId
) {
    public enum LockboxProfileStatus {
        ENABLED
    }

    public enum LockboxDeviceStatus {
        ACTIVE
    }
}