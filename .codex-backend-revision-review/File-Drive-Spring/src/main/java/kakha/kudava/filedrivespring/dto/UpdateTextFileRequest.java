package kakha.kudava.filedrivespring.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class UpdateTextFileRequest {
    private String content;
    private String expectedChecksum;
}
