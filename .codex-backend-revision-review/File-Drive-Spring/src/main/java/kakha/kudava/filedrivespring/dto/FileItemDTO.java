package kakha.kudava.filedrivespring.dto;

import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Setter
@Getter
public class FileItemDTO {
    private Long id;
    private String fileName;
    //private String objectKey;
    private String objectType;
    private Long parentId;
    private Long size;
    private boolean deleted;
    private boolean shared;
    private Instant creationDate;
    private Instant lastModifiedDate;
    private String ownerUsername;
}
