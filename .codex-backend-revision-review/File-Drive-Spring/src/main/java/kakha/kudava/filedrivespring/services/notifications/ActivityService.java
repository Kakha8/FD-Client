package kakha.kudava.filedrivespring.services.notifications;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import kakha.kudava.filedrivespring.dto.ActivityItem;
import kakha.kudava.filedrivespring.dto.ActivityItem.ActivityDetail;
import kakha.kudava.filedrivespring.enums.ActionType;
import kakha.kudava.filedrivespring.enums.EntityType;
import kakha.kudava.filedrivespring.model.ActionLogs;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.ActionLogsRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

@Service
@Transactional(readOnly = true)
public class ActivityService {

    private static final TypeReference<
            Map<String, Object>
            > MAP_TYPE =
            new TypeReference<>() {
            };

    private static final Pattern UUID_PREFIX =
            Pattern.compile(
                    "^[0-9a-fA-F]{8}-"
                            + "[0-9a-fA-F]{4}-"
                            + "[0-9a-fA-F]{4}-"
                            + "[0-9a-fA-F]{4}-"
                            + "[0-9a-fA-F]{12}-"
            );

    private final ActionLogsRepository actionLogsRepository;
    private final ObjectMapper objectMapper;

    public ActivityService(
            ActionLogsRepository actionLogsRepository,
            ObjectMapper objectMapper
    ) {
        this.actionLogsRepository =
                actionLogsRepository;

        this.objectMapper =
                objectMapper;
    }

    public Page<ActivityItem> getRecentActivity(
            User user,
            Pageable pageable
    ) {
        return getRecentActivity(
                user,
                pageable,
                null,
                null,
                Set.of()
        );
    }

    public Page<ActivityItem> getRecentActivity(
            User user,
            Pageable pageable,
            Instant from,
            Instant toExclusive,
            Set<ActionType> types
    ) {
        Objects.requireNonNull(
                user,
                "user is required"
        );

        Objects.requireNonNull(
                pageable,
                "pageable is required"
        );

        Specification<ActionLogs> specification =
                (root, query, criteriaBuilder) ->
                        criteriaBuilder.equal(
                                root.get("user"),
                                user
                        );

        if (from != null) {
            specification =
                    specification.and(
                            (
                                    root,
                                    query,
                                    criteriaBuilder
                            ) ->
                                    criteriaBuilder
                                            .greaterThanOrEqualTo(
                                                    root.<Instant>get(
                                                            "timestamp"
                                                    ),
                                                    from
                                            )
                    );
        }

        if (toExclusive != null) {
            specification =
                    specification.and(
                            (
                                    root,
                                    query,
                                    criteriaBuilder
                            ) ->
                                    criteriaBuilder.lessThan(
                                            root.<Instant>get(
                                                    "timestamp"
                                            ),
                                            toExclusive
                                    )
                    );
        }

        if (
                types != null &&
                        !types.isEmpty()
        ) {
            specification =
                    specification.and(
                            (
                                    root,
                                    query,
                                    criteriaBuilder
                            ) ->
                                    root.<ActionType>get(
                                                    "action"
                                            )
                                            .in(types)
                    );
        }

        return actionLogsRepository
                .findAll(
                        specification,
                        pageable
                )
                .map(this::toActivityItem);
    }

    public List<ActivityItem> getLast1000Activities(
            User user
    ) {
        Objects.requireNonNull(
                user,
                "user is required"
        );

        return actionLogsRepository
                .findTop1000ByUserOrderByTimestampDesc(
                        user
                )
                .stream()
                .map(this::toActivityItem)
                .toList();
    }

    private ActivityItem toActivityItem(
            ActionLogs log
    ) {
        Map<String, Object> metadata =
                parseDetails(
                        log.getDetails()
                );

        String actionName =
                actionName(
                        log.getAction()
                );

        String resourceName =
                firstText(
                        metadata,
                        "name",
                        "resourceName",
                        "fileName",
                        "folderName",
                        "newName"
                );

        resourceName =
                cleanName(resourceName);

        String title =
                buildTitle(actionName);

        String summary =
                buildSummary(
                        actionName,
                        resourceName,
                        log.getEntityType()
                );

        return new ActivityItem(
                log.getId(),
                log.getAction(),
                title,
                summary,
                log.getEntityType(),
                log.getEntityId(),
                resourceName,
                log.getTimestamp(),
                buildDetails(
                        log,
                        actionName,
                        metadata
                )
        );
    }

    private Map<String, Object> parseDetails(
            String details
    ) {
        if (
                details == null ||
                        details.isBlank()
        ) {
            return Map.of();
        }

        try {
            return objectMapper.readValue(
                    details,
                    MAP_TYPE
            );
        } catch (Exception ignored) {
            Map<String, Object> fallback =
                    new LinkedHashMap<>();

            fallback.put(
                    "description",
                    details.trim()
            );

            return fallback;
        }
    }

    private String buildTitle(
            String action
    ) {
        if (
                contains(action, "PERMANENT") &&
                        contains(action, "DELETE")
        ) {
            return "Permanent delete";
        }

        if (contains(action, "RESTORE")) {
            return "Restored from Trash";
        }

        if (
                contains(action, "TRASH") ||
                        action.equals("DELETE")
        ) {
            return "Moved to Trash";
        }

        if (contains(action, "UPLOAD")) {
            return "Upload complete";
        }

        if (
                contains(action, "CREATE") &&
                        contains(action, "FOLDER")
        ) {
            return "Folder created";
        }

        if (contains(action, "RENAME")) {
            return "Item renamed";
        }

        if (
                contains(action, "FAVORITE") &&
                        (
                                contains(action, "ADD") ||
                                        contains(action, "ADDED")
                        )
        ) {
            return "Added to Favorites";
        }

        if (
                contains(action, "FAVORITE") &&
                        (
                                contains(action, "REMOVE") ||
                                        contains(action, "REMOVED")
                        )
        ) {
            return "Removed from Favorites";
        }

        if (contains(action, "MOVE")) {
            return "Item moved";
        }

        return humanize(action);
    }

    private String buildSummary(
            String action,
            String resourceName,
            EntityType entityType
    ) {
        String item =
                resourceName == null
                        ? entityType == EntityType.FOLDER
                        ? "The folder"
                        : "The item"
                        : quote(resourceName);

        if (
                contains(action, "PERMANENT") &&
                        contains(action, "DELETE")
        ) {
            return item
                    + " was permanently removed from Trash.";
        }

        if (contains(action, "RESTORE")) {
            return item
                    + " was restored successfully.";
        }

        if (
                contains(action, "TRASH") ||
                        action.equals("DELETE")
        ) {
            return item
                    + " was moved to Trash.";
        }

        if (contains(action, "UPLOAD")) {
            return item
                    + " was uploaded successfully.";
        }

        if (
                contains(action, "CREATE") &&
                        contains(action, "FOLDER")
        ) {
            return item
                    + " was created.";
        }

        if (contains(action, "RENAME")) {
            return item
                    + " was renamed.";
        }

        if (
                contains(action, "FAVORITE") &&
                        (
                                contains(action, "ADD") ||
                                        contains(action, "ADDED")
                        )
        ) {
            return item
                    + " was added to Favorites.";
        }

        if (
                contains(action, "FAVORITE") &&
                        (
                                contains(action, "REMOVE") ||
                                        contains(action, "REMOVED")
                        )
        ) {
            return item
                    + " was removed from Favorites.";
        }

        return item
                + " was updated.";
    }

    private List<ActivityDetail> buildDetails(
            ActionLogs log,
            String action,
            Map<String, Object> metadata
    ) {
        List<ActivityDetail> details =
                new ArrayList<>();

        String oldName =
                cleanName(
                        firstText(
                                metadata,
                                "oldName",
                                "previousName",
                                "fromName"
                        )
                );

        String newName =
                cleanName(
                        firstText(
                                metadata,
                                "newName",
                                "name",
                                "resourceName",
                                "fileName",
                                "folderName"
                        )
                );

        if (
                contains(action, "RENAME") &&
                        oldName != null
        ) {
            addDetail(
                    details,
                    "Previous name",
                    oldName
            );
        }

        if (
                contains(action, "RENAME") &&
                        newName != null
        ) {
            addDetail(
                    details,
                    "New name",
                    newName
            );
        }

        addDetail(
                details,
                "Original location",
                displayLocation(
                        firstText(
                                metadata,
                                "originalObjectKey",
                                "originalPath",
                                "sourcePath"
                        )
                )
        );

        addDetail(
                details,
                "Restored to",
                displayLocation(
                        firstText(
                                metadata,
                                "restoredObjectKey",
                                "restoredPath",
                                "destinationPath"
                        )
                )
        );

        addDetail(
                details,
                "Uploaded to",
                displayLocation(
                        firstText(
                                metadata,
                                "objectKey",
                                "uploadedObjectKey",
                                "targetPath"
                        )
                )
        );

        addDetail(
                details,
                "Moved to Trash",
                displayInstant(
                        firstText(
                                metadata,
                                "deletedAt",
                                "movedToTrashAt",
                                "trashedAt"
                        )
                )
        );

        addDetail(
                details,
                "Restored",
                displayInstant(
                        firstText(
                                metadata,
                                "restoredAt"
                        )
                )
        );

        addDetail(
                details,
                "Permanently deleted",
                displayInstant(
                        firstText(
                                metadata,
                                "permanentlyDeletedAt",
                                "deletedPermanentlyAt"
                        )
                )
        );

        addDetail(
                details,
                "Uploaded",
                displayInstant(
                        firstText(
                                metadata,
                                "uploadedAt",
                                "createdAt"
                        )
                )
        );

        String description =
                firstText(
                        metadata,
                        "description",
                        "reason"
                );

        if (
                description != null &&
                        !looksLikeJson(description)
        ) {
            addDetail(
                    details,
                    "Description",
                    description
            );
        }

        if (
                log.getFromFolderId() != null &&
                        log.getToFolderId() != null
        ) {
            addDetail(
                    details,
                    "Movement",
                    "Moved between folders"
            );
        }

        return List.copyOf(details);
    }

    private String displayLocation(
            String objectKey
    ) {
        if (
                objectKey == null ||
                        objectKey.isBlank()
        ) {
            return null;
        }

        String normalized =
                objectKey
                        .trim()
                        .replace('\\', '/');

        String[] rawParts =
                normalized.split("/");

        List<String> parts =
                new ArrayList<>();

        for (String rawPart : rawParts) {
            if (
                    rawPart == null ||
                            rawPart.isBlank()
            ) {
                continue;
            }

            parts.add(
                    cleanName(rawPart)
            );
        }

        if (
                parts.size() >= 2 &&
                        parts.get(0)
                                .equalsIgnoreCase("users")
        ) {
            parts =
                    new ArrayList<>(
                            parts.subList(
                                    2,
                                    parts.size()
                            )
                    );
        }

        if (
                parts.size() >= 2 &&
                        parts.get(0)
                                .equalsIgnoreCase("files")
        ) {
            parts =
                    new ArrayList<>(
                            parts.subList(
                                    2,
                                    parts.size()
                            )
                    );
        }

        if (!parts.isEmpty()) {
            parts.remove(
                    parts.size() - 1
            );
        }

        if (parts.isEmpty()) {
            return "My Drive";
        }

        return "My Drive / "
                + String.join(
                " / ",
                parts
        );
    }

    private String displayInstant(
            String value
    ) {
        if (
                value == null ||
                        value.isBlank()
        ) {
            return null;
        }

        try {
            return Instant
                    .parse(value.trim())
                    .toString();
        } catch (
                DateTimeParseException ignored
        ) {
            return value.trim();
        }
    }

    private String firstText(
            Map<String, Object> metadata,
            String... keys
    ) {
        for (String key : keys) {
            Object value =
                    metadata.get(key);

            if (value == null) {
                continue;
            }

            String text =
                    value
                            .toString()
                            .trim();

            if (!text.isBlank()) {
                return text;
            }
        }

        return null;
    }

    private void addDetail(
            List<ActivityDetail> details,
            String label,
            String value
    ) {
        if (
                value == null ||
                        value.isBlank()
        ) {
            return;
        }

        details.add(
                new ActivityDetail(
                        label,
                        value
                )
        );
    }

    private String cleanName(
            String value
    ) {
        if (
                value == null ||
                        value.isBlank()
        ) {
            return null;
        }

        String cleaned =
                value
                        .trim()
                        .replace('\\', '/');

        int slash =
                cleaned.lastIndexOf('/');

        if (
                slash >= 0 &&
                        slash < cleaned.length() - 1
        ) {
            cleaned =
                    cleaned.substring(
                            slash + 1
                    );
        }

        return UUID_PREFIX
                .matcher(cleaned)
                .replaceFirst("");
    }

    private String actionName(
            ActionType action
    ) {
        return action == null
                ? "ACTIVITY"
                : action
                .name()
                .toUpperCase(
                        Locale.ROOT
                );
    }

    private String humanize(
            String value
    ) {
        String text =
                value
                        .toLowerCase(Locale.ROOT)
                        .replace('_', ' ');

        return Character.toUpperCase(
                text.charAt(0)
        ) + text.substring(1);
    }

    private boolean contains(
            String value,
            String token
    ) {
        return value != null &&
                value.contains(token);
    }

    private boolean looksLikeJson(
            String value
    ) {
        String trimmed =
                value.trim();

        return (
                trimmed.startsWith("{") &&
                        trimmed.endsWith("}")
        ) || (
                trimmed.startsWith("[") &&
                        trimmed.endsWith("]")
        );
    }

    private String quote(
            String value
    ) {
        return "\""
                + value
                + "\"";
    }
}