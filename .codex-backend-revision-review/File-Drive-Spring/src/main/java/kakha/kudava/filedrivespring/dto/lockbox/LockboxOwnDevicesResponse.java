package kakha.kudava.filedrivespring.dto.lockbox;

import java.util.List;

public record LockboxOwnDevicesResponse(List<LockboxOwnDeviceResponse> devices) {
    public LockboxOwnDevicesResponse {
        devices = devices == null ? List.of() : List.copyOf(devices);
    }
}
