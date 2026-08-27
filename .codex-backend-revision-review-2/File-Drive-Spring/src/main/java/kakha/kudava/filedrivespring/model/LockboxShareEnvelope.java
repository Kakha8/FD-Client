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
        name = "lockbox_share_envelopes",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_lockbox_share_recipient_key",
                        columnNames = {
                                "share_id",
                                "recipient_key_id"
                        }
                )
        },
        indexes = {
                @Index(
                        name = "idx_lockbox_envelope_share",
                        columnList = "share_id"
                ),
                @Index(
                        name = "idx_lockbox_envelope_recipient_key",
                        columnList = "recipient_key_id"
                )
        }
)
public class LockboxShareEnvelope {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "share_id",
            nullable = false,
            updatable = false,
            foreignKey = @ForeignKey(
                    name = "fk_lockbox_envelope_share"
            )
    )
    private LockboxShare share;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "recipient_key_id",
            nullable = false,
            updatable = false,
            foreignKey = @ForeignKey(
                    name = "fk_lockbox_envelope_recipient_key"
            )
    )
    private LockboxKey recipientKey;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "owner_signing_key_id",
            nullable = false,
            updatable = false,
            foreignKey = @ForeignKey(
                    name = "fk_lockbox_envelope_owner_signing_key"
            )
    )
    private LockboxKey ownerSigningKey;

    @Getter(AccessLevel.NONE)
    @Lob
    @Basic(fetch = FetchType.LAZY)
    @Column(
            name = "envelope",
            nullable = false,
            updatable = false
    )
    private byte[] envelope;

    @Getter(AccessLevel.NONE)
    @Lob
    @Basic(fetch = FetchType.LAZY)
    @Column(
            name = "owner_signature",
            nullable = false,
            updatable = false
    )
    private byte[] ownerSignature;

    @Column(
            name = "created_at",
            nullable = false,
            updatable = false
    )
    private Instant createdAt;

    public LockboxShareEnvelope(
            LockboxShare share,
            LockboxKey recipientKey,
            LockboxKey ownerSigningKey,
            byte[] envelope,
            byte[] ownerSignature
    ) {
        this.share = Objects.requireNonNull(
                share,
                "share"
        );

        this.recipientKey = Objects.requireNonNull(
                recipientKey,
                "recipientKey"
        );

        this.ownerSigningKey = Objects.requireNonNull(
                ownerSigningKey,
                "ownerSigningKey"
        );

        this.envelope = requireBytes(envelope, 1858, "envelope");

        this.ownerSignature = requireBytes(ownerSignature, 4627, "owner signature");

        validateKeys();
    }

    public byte[] getEnvelope() {
        return envelope.clone();
    }

    public byte[] getOwnerSignature() {
        return ownerSignature.clone();
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
                share,
                "share"
        );

        Objects.requireNonNull(
                recipientKey,
                "recipientKey"
        );

        Objects.requireNonNull(
                ownerSigningKey,
                "ownerSigningKey"
        );

        envelope = requireBytes(envelope, 1858, "envelope");
        ownerSignature = requireBytes(ownerSignature, 4627, "owner signature");

        validateKeys();
    }

    private void validateKeys() {
        if (recipientKey.getRole()
                != LockboxKey.Role.ENCRYPTION
                || recipientKey.getAlgorithm()
                != LockboxKey.Algorithm.ML_KEM_1024) {

            throw new IllegalArgumentException(
                    "The recipient key must be an ML-KEM-1024 encryption key."
            );
        }

        if (recipientKey.getStatus() != LockboxKey.Status.ACTIVE) {
            throw new IllegalArgumentException("The recipient key must be active.");
        }

        if (ownerSigningKey.getRole()
                != LockboxKey.Role.SIGNING
                || ownerSigningKey.getAlgorithm()
                != LockboxKey.Algorithm.ML_DSA_87) {

            throw new IllegalArgumentException(
                    "The owner key must be an ML-DSA-87 signing key."
            );
        }

        if (ownerSigningKey.getStatus() != LockboxKey.Status.ACTIVE) {
            throw new IllegalArgumentException("The owner signing key must be active.");
        }
    }

    private static byte[] requireBytes(
            byte[] value,
            int expectedLength,
            String field
    ) {
        if (value == null || value.length != expectedLength) {
            throw new IllegalArgumentException(
                    field + " must contain exactly " + expectedLength + " bytes."
            );
        }

        return value.clone();
    }
}
