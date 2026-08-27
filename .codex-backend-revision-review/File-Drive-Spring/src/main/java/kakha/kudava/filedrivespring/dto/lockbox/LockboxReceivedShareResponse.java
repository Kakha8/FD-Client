package kakha.kudava.filedrivespring.dto.lockbox;

import java.time.Instant;

public record LockboxReceivedShareResponse(
        String shareId,
        Long fileId,
        String clientFileId,
        long revision,
        String ownerUsername,
        String permission,
        Instant createdAt,
        Instant expiresAt,
        String recipientEnvelope,
        String ownerSigningKeyId,
        String ownerSigningPublicKey,
        String ownerShareSignature,
        String manifest,
        String fileSignature,
        String encryptedHeader
) {
}