package kakha.kudava.filedrivespring.dto.lockbox;

import java.util.List;

public record LockboxFolderViewResponse(
        Long id,
        String name,
        Long parentId,
        List<LockboxFolderItemResponse> folders,
        List<LockboxFileItemResponse> files
) {
    public LockboxFolderViewResponse {
        folders = List.copyOf(folders);
        files = List.copyOf(files);
    }
}
