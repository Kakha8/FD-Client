package kakha.kudava.filedrivespring.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class FavoritesRequestDTO {
    private List<Long> fileIds;
    private List<Long> folderIds;
}
