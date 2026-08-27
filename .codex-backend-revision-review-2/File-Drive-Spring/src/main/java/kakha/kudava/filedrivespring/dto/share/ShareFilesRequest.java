package kakha.kudava.filedrivespring.dto.share;

import kakha.kudava.filedrivespring.enums.SharingRole;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class ShareFilesRequest {
    private List<Long> fileIds;
    private String username;
    private SharingRole role;
}