package kakha.kudava.filedrivespring.dto.share;

import kakha.kudava.filedrivespring.enums.SharingRole;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class ShareRequestDTO {
    private List<Long> fileIds;
    private List<Long> folderIds;
    private String targetUsername;
    private SharingRole role;
}