package kakha.kudava.filedrivespring.dto.lockbox;

import java.util.UUID;

public record LockboxPrivateMetadataResponse(
        Long id,
        UUID clientFileId,
        long revision,
        String manifest,
        String signature,
        String encryptedHeader
) {}