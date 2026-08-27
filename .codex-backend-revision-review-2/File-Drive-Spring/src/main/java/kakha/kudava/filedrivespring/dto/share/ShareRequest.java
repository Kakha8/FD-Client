package kakha.kudava.filedrivespring.dto.share;

import kakha.kudava.filedrivespring.enums.SharingRole;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ShareRequest {
    private String username;
    private SharingRole role;
}
