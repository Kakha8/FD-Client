package kakha.kudava.filedrivespring.model;

import jakarta.persistence.*;
import kakha.kudava.filedrivespring.enums.EntityType;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Objects;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(
        name = "favorites",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_favorites_user_target",
                        columnNames = {"user_id", "entity_type", "entity_id"}
                )
        },
        indexes = {
                @Index(
                        name = "idx_favorites_user_active",
                        columnList = "user_id, removed_at"
                ),
                @Index(
                        name = "idx_favorites_target",
                        columnList = "entity_type, entity_id"
                )
        }
)
public class Favorites {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(name = "entity_type", nullable = false, length = 20)
    private EntityType entityType;

    @Column(name = "entity_id", nullable = false)
    private Long entityId;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "removed_at")
    private Instant removedAt;

    public Favorites(User user, EntityType entityType, Long entityId) {
        this.user = Objects.requireNonNull(user);
        this.entityType = Objects.requireNonNull(entityType);
        this.entityId = Objects.requireNonNull(entityId);
    }

    @PrePersist
    private void initializeCreatedAt() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    public boolean isActive() {
        return removedAt == null;
    }

    public void remove() {
        if (removedAt == null) {
            removedAt = Instant.now();
        }
    }

    public void restore() {
        removedAt = null;
    }
}