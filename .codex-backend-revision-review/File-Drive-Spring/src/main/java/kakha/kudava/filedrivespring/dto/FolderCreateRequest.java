package kakha.kudava.filedrivespring.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FolderCreateRequest {
    private String name;
    private Long parentId; // null = root
}