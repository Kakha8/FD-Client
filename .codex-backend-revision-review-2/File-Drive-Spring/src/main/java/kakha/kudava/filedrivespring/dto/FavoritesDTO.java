package kakha.kudava.filedrivespring.dto;

import kakha.kudava.filedrivespring.enums.EntityType;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
public class FavoritesDTO {

    private Long id;
    private EntityType entityType;
    private Long entityId;

    private String name;
    private String objectType;
    private Long size;
    private String ownerUsername;

    private Instant createdAt;
}