package kakha.kudava.filedrivespring.dto.lockbox;

public record LockboxOwnDeviceKeyResponse(
        String keyId,
        String algorithm,
        String publicKey
) {
}
