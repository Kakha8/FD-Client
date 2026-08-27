package kakha.kudava.filedrivespring.dto.lockbox;

import java.util.List;

public record LockboxPrivateMetadataListResponse(
        List<LockboxPrivateMetadataResponse> files
) {
    public LockboxPrivateMetadataListResponse {
        files = List.copyOf(files);
    }
}