package kakha.kudava.filedrivespring.dto;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class FolderRenameRequest {
    private Long id;
    private String newName;

    public FolderRenameRequest(String newName) {
        this.newName = newName;
    }
}
