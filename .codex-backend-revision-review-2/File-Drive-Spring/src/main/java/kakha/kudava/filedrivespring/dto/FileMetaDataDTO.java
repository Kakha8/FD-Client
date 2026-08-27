package kakha.kudava.filedrivespring.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class FileMetaDataDTO {
    private Long id;
    private String objectKey;
    private String objectType;
    private boolean deleted;
    private Long parentId;
    private String fileName;
    private Long size;
}
