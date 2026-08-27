package kakha.kudava.filedrivespring.dto.lockbox;

import java.util.List;
import java.util.UUID;

public record LockboxRecipientKeysResponse(
        Long recipientId,
        UUID recipientPublicUuid,
        String username,
        List<LockboxRecipientKeyResponse> encryptionKeys
) {
}
