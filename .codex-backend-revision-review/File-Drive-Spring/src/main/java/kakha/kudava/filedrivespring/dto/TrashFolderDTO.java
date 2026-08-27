package kakha.kudava.filedrivespring.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class TrashFolderDTO {
    private Long id;
    private String name;
    private String prefix;
}