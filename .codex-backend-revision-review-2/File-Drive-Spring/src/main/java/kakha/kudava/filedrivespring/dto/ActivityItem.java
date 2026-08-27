package kakha.kudava.filedrivespring.dto;
import kakha.kudava.filedrivespring.enums.ActionType;
import kakha.kudava.filedrivespring.enums.EntityType;

import java.time.Instant;
import java.util.List;

public record ActivityItem(
        Long id,
        ActionType type,
        String title,
        String summary,
        EntityType entityType,
        Long entityId,
        String resourceName,
        Instant createdAt,
        List<ActivityDetail> details
) {
    public record ActivityDetail(
            String label,
            String value
    ) {
    }
}