package kakha.kudava.fdclient.service;

import java.util.Objects;

public record LockboxRecipientEncryptionKey(
        byte[] keyId,
        Algorithm algorithm,
        byte[] publicKey
) {

    public LockboxRecipientEncryptionKey {
        keyId = Objects.requireNonNull(keyId, "keyId").clone();
        algorithm = Objects.requireNonNull(algorithm, "algorithm");
        publicKey = Objects.requireNonNull(publicKey, "publicKey").clone();
    }

    @Override
    public byte[] keyId() {
        return keyId.clone();
    }

    @Override
    public byte[] publicKey() {
        return publicKey.clone();
    }

    public enum Algorithm {
        ML_KEM_1024
    }
}
