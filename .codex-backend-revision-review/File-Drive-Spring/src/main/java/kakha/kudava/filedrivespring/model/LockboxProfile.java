package kakha.kudava.filedrivespring.model;


import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Objects;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(
        name = "lockbox_profiles",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_cse_profiles_user_id",
                        columnNames = "user_id"
                )
        }
)
public class LockboxProfile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "user_id",
            nullable = false,
            updatable = false,
            foreignKey = @ForeignKey(
                    name = "fk_cse_profiles_user"
            )
    )
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(
            name = "status",
            nullable = false,
            length = 20
    )
    private Status status;

    @Column(
            name = "enabled_at",
            nullable = false,
            updatable = false
    )
    private Instant enabledAt;

    @Column(
            name = "created_at",
            nullable = false,
            updatable = false
    )
    private Instant createdAt;

    @Column(
            name = "updated_at",
            nullable = false
    )
    private Instant updatedAt;

    public LockboxProfile(User user) {
        this.user = Objects.requireNonNull(user, "user");
        this.status = Status.ENABLED;
    }

    public void suspend() {
        status = Status.SUSPENDED;
    }

    public void enable() {
        status = Status.ENABLED;

        if (enabledAt == null) {
            enabledAt = Instant.now();
        }
    }

    @PrePersist
    private void beforeInsert() {
        Objects.requireNonNull(user, "user");
        Objects.requireNonNull(status, "status");

        Instant now = Instant.now();

        createdAt = now;
        updatedAt = now;

        if (status == Status.ENABLED && enabledAt == null) {
            enabledAt = now;
        }
    }

    @PreUpdate
    private void beforeUpdate() {
        Objects.requireNonNull(user, "user");
        Objects.requireNonNull(status, "status");

        updatedAt = Instant.now();
    }

    public enum Status {
        ENABLED,
        SUSPENDED
    }
}