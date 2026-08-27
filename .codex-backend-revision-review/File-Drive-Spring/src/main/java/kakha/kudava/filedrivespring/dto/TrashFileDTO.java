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
public class TrashFileDTO {
    private Long id;
    private String fileName;
    private String objectType;
    private Long size;
    private Instant creationDate;
    private String objectKey;
    private String originalObjectKey;
}