package kakha.kudava.fdclient.service;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

public record LockboxRecipientKeys(
        long recipientId,
        UUID recipientPublicUuid,
        String username,
        List<LockboxRecipientEncryptionKey> encryptionKeys
) {

    public LockboxRecipientKeys {
        if (recipientId < 1) {
            throw new IllegalArgumentException("recipientId must be positive");
        }

        recipientPublicUuid = Objects.requireNonNull(
                recipientPublicUuid,
                "recipientPublicUuid"
        );

        username = Objects.requireNonNull(username, "username");
        encryptionKeys = List.copyOf(
                Objects.requireNonNull(encryptionKeys, "encryptionKeys")
        );

        if (encryptionKeys.isEmpty()) {
            throw new IllegalArgumentException(
                    "At least one recipient encryption key is required."
            );
        }
    }

    public LockboxRecipientEncryptionKey primaryEncryptionKey() {
        return encryptionKeys.getFirst();
    }
}
