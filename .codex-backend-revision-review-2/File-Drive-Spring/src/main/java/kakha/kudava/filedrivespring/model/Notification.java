package kakha.kudava.filedrivespring.model;

import jakarta.persistence.*;
import kakha.kudava.filedrivespring.enums.EntityType;
import kakha.kudava.filedrivespring.enums.NotificationType;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Objects;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(
        name = "notifications",
        indexes = {
                @Index(
                        name = "idx_notifications_recipient_created",
                        columnList = "recipient_id, created_at"
                ),
                @Index(
                        name = "idx_notifications_recipient_unread",
                        columnList = "recipient_id, read_at, removed_at"
                ),
                @Index(
                        name = "idx_notifications_target",
                        columnList = "entity_type, entity_id"
                )
        }
)
public class Notification {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "recipient_id", nullable = false)
    private User recipient;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "actor_id")
    private User actor;

    /**
     * Snapshot of the actor's username so old notifications remain useful
     * even if the account is later renamed or removed.
     */
    @Column(name = "actor_username", length = 100)
    private String actorUsername;

    @Enumerated(EnumType.STRING)
    @Column(name = "notification_type", nullable = false, length = 50)
    private NotificationType type;

    @Column(nullable = false, length = 160)
    private String title;

    @Column(nullable = false, columnDefinition = "TEXT")
    private String message;

    @Enumerated(EnumType.STRING)
    @Column(name = "entity_type", length = 20)
    private EntityType entityType;

    @Column(name = "entity_id")
    private Long entityId;

    /*
     * User-facing context snapshots.
     *
     * These fields intentionally duplicate selected resource information.
     * A notification should still explain what happened after a file is
     * renamed, deleted, or the recipient loses access.
     */
    @Column(name = "resource_name", length = 255)
    private String resourceName;

    @Column(name = "resource_mime_type", length = 255)
    private String resourceMimeType;

    @Column(name = "resource_size")
    private Long resourceSize;

    @Column(name = "resource_path", length = 1000)
    private String resourcePath;

    @Column(name = "permission_role", length = 30)
    private String permissionRole;

    @Column(name = "security_status", length = 30)
    private String securityStatus;

    @Column(name = "security_threat", length = 500)
    private String securityThreat;

    @Column(name = "failure_reason", length = 500)
    private String failureReason;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "read_at")
    private Instant readAt;

    @Column(name = "removed_at")
    private Instant removedAt;

    public Notification(
            User recipient,
            User actor,
            NotificationType type,
            String title,
            String message,
            EntityType entityType,
            Long entityId
    ) {
        this.recipient = Objects.requireNonNull(
                recipient,
                "recipient is required"
        );

        this.actor = actor;
        this.actorUsername =
                actor == null
                        ? null
                        : normalizeOptional(actor.getUsername(), 100);

        this.type = Objects.requireNonNull(
                type,
                "type is required"
        );

        this.title = requireText(title, "title", 160);
        this.message = requireText(message, "message", null);
        this.entityType = entityType;
        this.entityId = entityId;

        if ((entityType == null) != (entityId == null)) {
            throw new IllegalArgumentException(
                    "entityType and entityId must either both be set or both be null"
            );
        }
    }

    @PrePersist
    private void initializeCreatedAt() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    public void setResourceDetails(
            String resourceName,
            String resourceMimeType,
            Long resourceSize,
            String resourcePath
    ) {
        this.resourceName =
                normalizeOptional(resourceName, 255);

        this.resourceMimeType =
                normalizeOptional(resourceMimeType, 255);

        this.resourceSize =
                resourceSize != null && resourceSize >= 0
                        ? resourceSize
                        : null;

        this.resourcePath =
                normalizeOptional(resourcePath, 1000);
    }

    public void setPermissionRole(String permissionRole) {
        this.permissionRole =
                normalizeOptional(permissionRole, 30);
    }

    public void setSecurityDetails(
            String securityStatus,
            String securityThreat
    ) {
        this.securityStatus =
                normalizeOptional(securityStatus, 30);

        this.securityThreat =
                normalizeOptional(securityThreat, 500);
    }

    public void setFailureReason(String failureReason) {
        this.failureReason =
                normalizeOptional(failureReason, 500);
    }

    public boolean isRead() {
        return readAt != null;
    }

    public boolean isActive() {
        return removedAt == null;
    }

    public void markRead() {
        if (readAt == null) {
            readAt = Instant.now();
        }
    }

    public void markUnread() {
        readAt = null;
    }

    public void remove() {
        if (removedAt == null) {
            removedAt = Instant.now();
        }
    }

    public void restore() {
        removedAt = null;
    }

    private static String requireText(
            String value,
            String fieldName,
            Integer maximumLength
    ) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    fieldName + " is required"
            );
        }

        String trimmed = value.trim();

        if (
                maximumLength != null &&
                        trimmed.length() > maximumLength
        ) {
            throw new IllegalArgumentException(
                    fieldName +
                            " must not exceed " +
                            maximumLength +
                            " characters"
            );
        }

        return trimmed;
    }

    private static String normalizeOptional(
            String value,
            int maximumLength
    ) {
        if (value == null || value.isBlank()) {
            return null;
        }

        String trimmed = value.trim();

        if (trimmed.length() <= maximumLength) {
            return trimmed;
        }

        return trimmed.substring(0, maximumLength);
    }
}