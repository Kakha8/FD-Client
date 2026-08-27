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
        name = "lockbox_keys",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_cse_keys_key_id",
                        columnNames = "key_id"
                )
        },
        indexes = {
                @Index(
                        name = "idx_cse_keys_device_id",
                        columnList = "device_id"
                ),
                @Index(
                        name = "idx_cse_keys_device_role_status",
                        columnList = "device_id, key_role, status"
                )
        }
)
public class LockboxKey {

    public static final int KEY_ID_LENGTH = 32;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "device_id",
            nullable = false,
            updatable = false,
            foreignKey = @ForeignKey(
                    name = "fk_cse_keys_device"
            )
    )
    private LockboxDevice device;

    @Enumerated(EnumType.STRING)
    @Column(
            name = "key_role",
            nullable = false,
            updatable = false,
            length = 20
    )
    private Role role;

    @Enumerated(EnumType.STRING)
    @Column(
            name = "algorithm",
            nullable = false,
            updatable = false,
            length = 30
    )
    private Algorithm algorithm;

    @Getter(AccessLevel.NONE)
    @Column(
            name = "key_id",
            nullable = false,
            updatable = false,
            length = KEY_ID_LENGTH
    )
    private byte[] keyId;

    @Getter(AccessLevel.NONE)
    @Lob
    @Basic(fetch = FetchType.LAZY)
    @Column(
            name = "public_key",
            nullable = false,
            updatable = false
    )
    private byte[] publicKey;

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

    @Column(name = "retired_at")
    private Instant retiredAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    public LockboxKey(
            LockboxDevice device,
            Role role,
            Algorithm algorithm,
            byte[] keyId,
            byte[] publicKey
    ) {
        this.device = Objects.requireNonNull(
                device,
                "device"
        );

        this.role = Objects.requireNonNull(
                role,
                "role"
        );

        this.algorithm = Objects.requireNonNull(
                algorithm,
                "algorithm"
        );

        this.keyId = requireKeyId(keyId);
        this.publicKey = requirePublicKey(publicKey);
        this.status = Status.ACTIVE;

        validateRoleAndAlgorithm(role, algorithm);
    }

    public byte[] getKeyId() {
        return keyId.clone();
    }

    public byte[] getPublicKey() {
        return publicKey.clone();
    }

    public void retire() {
        if (status == Status.REVOKED) {
            throw new IllegalStateException(
                    "A revoked key cannot be retired."
            );
        }

        if (status == Status.RETIRED) {
            return;
        }

        status = Status.RETIRED;
        retiredAt = Instant.now();
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
        validateState();

        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    @PreUpdate
    private void beforeUpdate() {
        validateState();
    }

    private void validateState() {
        Objects.requireNonNull(device, "device");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(algorithm, "algorithm");
        Objects.requireNonNull(status, "status");

        keyId = requireKeyId(keyId);
        publicKey = requirePublicKey(publicKey);

        validateRoleAndAlgorithm(role, algorithm);
    }

    private static byte[] requireKeyId(byte[] value) {
        if (value == null || value.length != KEY_ID_LENGTH) {
            throw new IllegalArgumentException(
                    "CSE key ID must contain exactly 32 bytes."
            );
        }

        return value.clone();
    }

    private static byte[] requirePublicKey(byte[] value) {
        if (value == null || value.length == 0) {
            throw new IllegalArgumentException(
                    "CSE public key is required."
            );
        }

        return value.clone();
    }

    private static void validateRoleAndAlgorithm(
            Role role,
            Algorithm algorithm
    ) {
        boolean valid =
                role == Role.ENCRYPTION
                        && algorithm == Algorithm.ML_KEM_1024
                        || role == Role.SIGNING
                        && algorithm == Algorithm.ML_DSA_87;

        if (!valid) {
            throw new IllegalArgumentException(
                    "The key role does not match its algorithm."
            );
        }
    }

    public enum Role {
        ENCRYPTION,
        SIGNING
    }

    public enum Algorithm {
        ML_KEM_1024,
        ML_DSA_87
    }

    public enum Status {
        ACTIVE,
        RETIRED,
        REVOKED
    }
}