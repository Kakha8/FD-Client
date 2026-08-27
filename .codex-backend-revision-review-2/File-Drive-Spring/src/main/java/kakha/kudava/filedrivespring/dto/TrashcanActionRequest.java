package kakha.kudava.filedrivespring.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class TrashcanActionRequest {
    private List<Long> fileIds;
    private List<Long> folderIds;
}
