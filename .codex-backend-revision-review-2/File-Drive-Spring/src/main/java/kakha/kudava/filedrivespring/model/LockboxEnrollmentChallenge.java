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
        name = "lockbox_enrollment_challenges",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_lockbox_enrollment_id",
                        columnNames = "enrollment_id"
                )
        },
        indexes = {
                @Index(
                        name = "idx_lockbox_challenge_user_status",
                        columnList = "user_id, status"
                ),
                @Index(
                        name = "idx_lockbox_challenge_expires_at",
                        columnList = "expires_at"
                )
        }
)
public class LockboxEnrollmentChallenge {

    public static final int CHALLENGE_HASH_LENGTH = 32;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(
            name = "enrollment_id",
            nullable = false,
            updatable = false
    )
    private UUID enrollmentId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "user_id",
            nullable = false,
            updatable = false,
            foreignKey = @ForeignKey(
                    name = "fk_lockbox_challenge_user"
            )
    )
    private User user;

    @Getter(AccessLevel.NONE)
    @Column(
            name = "challenge_hash",
            nullable = false,
            updatable = false,
            length = CHALLENGE_HASH_LENGTH
    )
    private byte[] challengeHash;

    @Column(name = "device_uuid", updatable = false)
    private UUID deviceUuid;

    @Column(name = "device_name", length = 100, updatable = false)
    private String deviceName;

    @Getter(AccessLevel.NONE)
    @Column(name = "installation_handle", length = 32, updatable = false)
    private byte[] installationHandle;

    @Enumerated(EnumType.STRING)
    @Column(
            name = "status",
            nullable = false,
            length = 20
    )
    private Status status;

    @Column(
            name = "created_at",
            nullable = false,
            updatable = false
    )
    private Instant createdAt;

    @Column(
            name = "expires_at",
            nullable = false,
            updatable = false
    )
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    public LockboxEnrollmentChallenge(
            User user,
            UUID enrollmentId,
            byte[] challengeHash,
            UUID deviceUuid,
            String deviceName,
            byte[] installationHandle,
            Instant expiresAt
    ) {
        this.user = Objects.requireNonNull(user, "user");
        this.enrollmentId = Objects.requireNonNull(
                enrollmentId,
                "enrollmentId"
        );
        this.challengeHash =
                requireChallengeHash(challengeHash);
        this.deviceUuid = Objects.requireNonNull(deviceUuid, "deviceUuid");
        this.deviceName = requireDeviceName(deviceName);
        this.installationHandle = requireInstallationHandle(installationHandle);
        this.expiresAt = Objects.requireNonNull(
                expiresAt,
                "expiresAt"
        );
        this.status = Status.PENDING;
    }

    public byte[] getChallengeHash() {
        return challengeHash.clone();
    }

    public byte[] getInstallationHandle() {
        return installationHandle == null ? null : installationHandle.clone();
    }

    public boolean isExpired(Instant now) {
        return !expiresAt.isAfter(now);
    }

    public void consume(Instant now) {
        Objects.requireNonNull(now, "now");

        if (status != Status.PENDING) {
            throw new IllegalStateException(
                    "Enrollment challenge is not pending."
            );
        }

        if (isExpired(now)) {
            status = Status.EXPIRED;

            throw new IllegalStateException(
                    "Enrollment challenge has expired."
            );
        }

        status = Status.CONSUMED;
        consumedAt = now;
    }

    public void cancel() {
        if (status == Status.PENDING) {
            status = Status.CANCELLED;
        }
    }

    @PrePersist
    private void beforeInsert() {
        Objects.requireNonNull(user, "user");
        Objects.requireNonNull(enrollmentId, "enrollmentId");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(status, "status");

        challengeHash =
                requireChallengeHash(challengeHash);
        if (installationHandle != null) {
            installationHandle = requireInstallationHandle(installationHandle);
        }

        if (createdAt == null) {
            createdAt = Instant.now();
        }

        if (!expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException(
                    "Challenge expiration must be after creation."
            );
        }
    }

    @PreUpdate
    private void beforeUpdate() {
        Objects.requireNonNull(status, "status");

        challengeHash =
                requireChallengeHash(challengeHash);
    }

    private static byte[] requireInstallationHandle(byte[] value) {
        if (value == null || value.length != 32) {
            throw new IllegalArgumentException("Installation handle must contain exactly 32 bytes.");
        }
        return value.clone();
    }

    private static String requireDeviceName(String value) {
        if (value == null || value.isBlank() || value.trim().length() > 100) {
            throw new IllegalArgumentException("Device name is invalid.");
        }
        return value.trim();
    }

    private static byte[] requireChallengeHash(byte[] value) {
        if (value == null
                || value.length != CHALLENGE_HASH_LENGTH) {
            throw new IllegalArgumentException(
                    "Challenge hash must contain exactly 32 bytes."
            );
        }

        return value.clone();
    }

    public enum Status {
        PENDING,
        CONSUMED,
        EXPIRED,
        CANCELLED
    }
}
