package kakha.kudava.filedrivespring.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class FolderViewDTO {
    private Long id;
    private String name;
    private String ownerUsername;

    private List<FolderItemDTO> folders;
    private List<FileItemDTO> files;
}
