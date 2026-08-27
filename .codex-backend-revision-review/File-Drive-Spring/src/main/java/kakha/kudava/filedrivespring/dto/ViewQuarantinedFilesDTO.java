package kakha.kudava.filedrivespring.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ViewQuarantinedFilesDTO {
    private Long id;
    private String originalFilename;
    private String objectKey;
    private String contentType;
    private Long size;
    private String checksum;
    private String clamAvResponse;
    private Long parentFolderId;
    private Long userId;
    private String username;
    private Instant createdAt;
}
