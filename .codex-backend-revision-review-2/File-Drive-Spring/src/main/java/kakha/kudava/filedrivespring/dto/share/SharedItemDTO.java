package kakha.kudava.filedrivespring.dto.share;

import kakha.kudava.filedrivespring.enums.SharingRole;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SharedItemDTO {
    private Long shareId;

    private String resourceType; // FILE or FOLDER
    private Long resourceId;
    private String name;

    private String ownerUsername;
    private String sharedWithUsername;

    private Long size;
    private SharingRole role;
}
