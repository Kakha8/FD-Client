package kakha.kudava.filedrivespring.model;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(
        name = "lockbox_shares",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_lockbox_share_uuid",
                        columnNames = "share_uuid"
                ),
                @UniqueConstraint(
                        name = "uk_lockbox_share_revision_target_device",
                        columnNames = {"lockbox_revision_id", "target_device_id"}
                )
        },
        indexes = {
                @Index(
                        name = "idx_lockbox_share_owner",
                        columnList = "owner_user_id"
                ),
                @Index(
                        name = "idx_lockbox_share_recipient_status",
                        columnList = "recipient_user_id, status"
                ),
                @Index(
                        name = "idx_lockbox_share_revision",
                        columnList = "lockbox_revision_id"
                ),
                @Index(
                        name = "idx_lockbox_share_target_status",
                        columnList = "target_device_id, status"
                ),
                @Index(
                        name = "idx_lockbox_share_recipient_target_status",
                        columnList = "recipient_user_id, target_device_id, status"
                )
        }
)
public class LockboxShare {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(
            name = "share_uuid",
            nullable = false,
            updatable = false
    )
    private UUID shareUuid;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "lockbox_revision_id",
            nullable = false,
            updatable = false,
            foreignKey = @ForeignKey(
                    name = "fk_lockbox_share_revision"
            )
    )
    private LockboxFileRevision revision;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "owner_user_id",
            nullable = false,
            updatable = false,
            foreignKey = @ForeignKey(
                    name = "fk_lockbox_share_owner"
            )
    )
    private User owner;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "recipient_user_id",
            nullable = false,
            updatable = false,
            foreignKey = @ForeignKey(
                    name = "fk_lockbox_share_recipient"
            )
    )
    private User recipient;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "target_device_id",
            nullable = false,
            updatable = false,
            foreignKey = @ForeignKey(name = "fk_lockbox_share_target_device")
    )
    private LockboxDevice targetDevice;

    @Enumerated(EnumType.STRING)
    @Column(
            name = "status",
            nullable = false,
            length = 20
    )
    private Status status;

    @Enumerated(EnumType.STRING)
    @Column(
            name = "permission",
            nullable = false,
            length = 20
    )
    private Permission permission;

    @Column(
            name = "created_at",
            nullable = false,
            updatable = false
    )
    private Instant createdAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "expires_at")
    private Instant expiresAt;

    public LockboxShare(
            UUID shareUuid,
            LockboxFileRevision revision,
            User owner,
            User recipient,
            LockboxDevice targetDevice,
            Permission permission,
            Instant expiresAt
    ) {
        this.shareUuid = Objects.requireNonNull(shareUuid, "shareUuid");

        this.revision = Objects.requireNonNull(
                revision,
                "revision"
        );

        this.owner = Objects.requireNonNull(
                owner,
                "owner"
        );

        this.recipient = Objects.requireNonNull(
                recipient,
                "recipient"
        );

        this.permission = Objects.requireNonNull(
                permission,
                "permission"
        );
        this.targetDevice = Objects.requireNonNull(targetDevice, "targetDevice");
        this.expiresAt = expiresAt;

        status = Status.ACTIVE;
    }

    public void revoke() {
        if (status == Status.REVOKED) {
            return;
        }

        status = Status.REVOKED;
        revokedAt = Instant.now();
    }

    @PrePersist
    private void beforeInsert() {
        validate();

        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    @PreUpdate
    private void beforeUpdate() {
        validate();
    }

    private void validate() {
        Objects.requireNonNull(
                shareUuid,
                "shareUuid"
        );

        Objects.requireNonNull(
                revision,
                "revision"
        );

        Objects.requireNonNull(
                owner,
                "owner"
        );

        Objects.requireNonNull(
                recipient,
                "recipient"
        );
        Objects.requireNonNull(targetDevice, "targetDevice");

        Objects.requireNonNull(
                status,
                "status"
        );

        Objects.requireNonNull(
                permission,
                "permission"
        );

        if (targetDevice.getProfile().getUser().getId() != null
                && recipient.getId() != null
                && !targetDevice.getProfile().getUser().getId().equals(recipient.getId())) {
            throw new IllegalStateException("Target device must belong to the recipient.");
        }
    }

    public enum Status {
        ACTIVE,
        REVOKED
    }

    public enum Permission {
        READ
    }
}
