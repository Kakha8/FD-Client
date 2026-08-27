package kakha.kudava.filedrivespring.dto.lockbox;

public record LockboxRecipientKeyResponse(
        String keyId,
        String algorithm,
        String publicKey
) {
}