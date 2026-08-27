package kakha.kudava.filedrivespring.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class MoveFolderRequest {
    private Long folderId;
    private Long targetFolderId;
}
