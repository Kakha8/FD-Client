package kakha.kudava.filedrivespring.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ViewTrashcanDTO {
    private List<TrashFileDTO> files;
    private List<TrashFolderDTO> folders;
}
