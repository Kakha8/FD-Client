package kakha.kudava.filedrivespring.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class FolderDTO {
    private Long id;
    private String name;
    private String prefix;
    private Long parentId;
    private List<FolderDTO> children;
}
