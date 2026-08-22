package kakha.kudava.fdclient.service;

import java.util.Objects;

public record LockboxShareGrant(
        byte[] envelope,
        byte[] ownerSigningKeyId,
        byte[] ownerSignature
) {
    public static final int ENVELOPE_LENGTH = 1_858;
    public static final int KEY_ID_LENGTH = 32;
    public static final int SIGNATURE_LENGTH = 4_627;

    public LockboxShareGrant {
        envelope = exact(envelope, ENVELOPE_LENGTH, "envelope");
        ownerSigningKeyId = exact(ownerSigningKeyId, KEY_ID_LENGTH, "ownerSigningKeyId");
        ownerSignature = exact(ownerSignature, SIGNATURE_LENGTH, "ownerSignature");
    }

    @Override public byte[] envelope() { return envelope.clone(); }
    @Override public byte[] ownerSigningKeyId() { return ownerSigningKeyId.clone(); }
    @Override public byte[] ownerSignature() { return ownerSignature.clone(); }

    private static byte[] exact(byte[] value, int length, String field) {
        Objects.requireNonNull(value, field);
        if (value.length != length) {
            throw new IllegalArgumentException(field + " must contain exactly " + length + " bytes.");
        }
        return value.clone();
    }
}
