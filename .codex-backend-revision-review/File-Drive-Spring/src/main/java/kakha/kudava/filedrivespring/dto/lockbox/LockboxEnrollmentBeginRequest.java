package kakha.kudava.filedrivespring.dto.lockbox;

import java.util.UUID;

public record LockboxEnrollmentBeginRequest(
        UUID deviceId,
        String installationHandle,
        String deviceName
) {
}
