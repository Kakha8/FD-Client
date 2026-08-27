package kakha.kudava.filedrivespring.dto.lockbox;

import java.util.UUID;

public record LockboxEnrollmentCompleteRequest(
        String challenge,
        UUID deviceId,
        String installationHandle,
        String deviceName,
        PublicKeyRequest encryptionKey,
        PublicKeyRequest signingKey,
        String signature
) {
    public record PublicKeyRequest(
            String algorithm,
            String keyId,
            String publicKey
    ) {
    }
}
