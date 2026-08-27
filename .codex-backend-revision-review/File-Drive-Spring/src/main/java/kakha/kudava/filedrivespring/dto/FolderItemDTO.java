package kakha.kudava.filedrivespring.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FolderItemDTO {
    private Long id;
    private String name;
    private String prefix;
    private boolean shared;
    private String ownerUsername;
}
