package kakha.kudava.filedrivespring.services.lockbox;

import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Component
public final class LockboxEnrollmentTranscript {

    private static final byte[] DOMAIN =
            "FD-LOCKBOX-DEVICE-ENROLLMENT-V2\0"
                    .getBytes(StandardCharsets.US_ASCII);

    private static final int CHALLENGE_LENGTH = 32;
    private static final int KEY_ID_LENGTH = 32;

    private static final int ML_KEM_1024_PUBLIC_KEY_LENGTH =
            1_568;

    private static final int ML_DSA_87_PUBLIC_KEY_LENGTH =
            2_592;

    private static final int ML_KEM_1024_ALGORITHM_ID = 1;
    private static final int ML_DSA_87_ALGORITHM_ID = 1;

    /**
     * Canonical enrollment transcript:
     *
     * domain                              fixed ASCII
     * enrollmentId                       16 RFC-4122 UUID bytes
     * challenge                          32 bytes
     * expiresAtUnixMillis                i64 little-endian
     * deviceId                           16 RFC-4122 UUID bytes
     * installationHandle                 32 bytes
     * deviceNameLength                   u16 little-endian
     * deviceName                         normalized UTF-8
     * encryptionAlgorithmId              u16 little-endian
     * encryptionKeyId                    32 bytes
     * encryptionPublicKeyLength          u32 little-endian
     * encryptionPublicKey                1568 bytes
     * signingAlgorithmId                 u16 little-endian
     * signingKeyId                       32 bytes
     * signingPublicKeyLength             u32 little-endian
     * signingPublicKey                   2592 bytes
     */
    public byte[] encode(
            UUID enrollmentId,
            byte[] challenge,
            Instant expiresAt,
            UUID deviceId,
            byte[] installationHandle,
            String deviceName,
            byte[] encryptionKeyId,
            byte[] encryptionPublicKey,
            byte[] signingKeyId,
            byte[] signingPublicKey
    ) {
        Objects.requireNonNull(
                enrollmentId,
                "enrollmentId"
        );
        Objects.requireNonNull(
                expiresAt,
                "expiresAt"
        );
        Objects.requireNonNull(
                deviceId,
                "deviceId"
        );

        requireLength(
                challenge,
                CHALLENGE_LENGTH,
                "challenge"
        );
        requireLength(installationHandle, 32, "installationHandle");

        requireLength(
                encryptionKeyId,
                KEY_ID_LENGTH,
                "encryptionKeyId"
        );

        requireLength(
                encryptionPublicKey,
                ML_KEM_1024_PUBLIC_KEY_LENGTH,
                "encryptionPublicKey"
        );

        requireLength(
                signingKeyId,
                KEY_ID_LENGTH,
                "signingKeyId"
        );

        requireLength(
                signingPublicKey,
                ML_DSA_87_PUBLIC_KEY_LENGTH,
                "signingPublicKey"
        );

        byte[] encodedDeviceName =
                encodeDeviceName(deviceName);

        ByteArrayOutputStream output =
                new ByteArrayOutputStream();

        output.writeBytes(DOMAIN);
        output.writeBytes(encodeUuid(enrollmentId));
        output.writeBytes(challenge);

        writeI64LittleEndian(
                output,
                expiresAt.toEpochMilli()
        );

        output.writeBytes(encodeUuid(deviceId));
        output.writeBytes(installationHandle);

        writeU16LittleEndian(
                output,
                encodedDeviceName.length
        );

        output.writeBytes(encodedDeviceName);

        writeU16LittleEndian(
                output,
                ML_KEM_1024_ALGORITHM_ID
        );

        output.writeBytes(encryptionKeyId);

        writeU32LittleEndian(
                output,
                encryptionPublicKey.length
        );

        output.writeBytes(encryptionPublicKey);

        writeU16LittleEndian(
                output,
                ML_DSA_87_ALGORITHM_ID
        );

        output.writeBytes(signingKeyId);

        writeU32LittleEndian(
                output,
                signingPublicKey.length
        );

        output.writeBytes(signingPublicKey);

        return output.toByteArray();
    }

    private byte[] encodeDeviceName(String deviceName) {
        if (deviceName == null) {
            throw new IllegalArgumentException(
                    "Device name is required."
            );
        }

        String normalized = deviceName.trim();

        if (normalized.isEmpty()) {
            throw new IllegalArgumentException(
                    "Device name is required."
            );
        }

        byte[] encoded =
                normalized.getBytes(StandardCharsets.UTF_8);

        if (encoded.length > 255) {
            throw new IllegalArgumentException(
                    "Device name cannot exceed 255 UTF-8 bytes."
            );
        }

        return encoded;
    }

    /**
     * UUIDs use their RFC-4122/network byte representation.
     * Integer fields elsewhere remain little-endian.
     */
    private byte[] encodeUuid(UUID uuid) {
        return ByteBuffer
                .allocate(16)
                .order(ByteOrder.BIG_ENDIAN)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits())
                .array();
    }

    private void writeU16LittleEndian(
            ByteArrayOutputStream output,
            int value
    ) {
        if (value < 0 || value > 0xFFFF) {
            throw new IllegalArgumentException(
                    "Value does not fit an unsigned 16-bit field."
            );
        }

        output.write(value & 0xFF);
        output.write((value >>> 8) & 0xFF);
    }

    private void writeU32LittleEndian(
            ByteArrayOutputStream output,
            long value
    ) {
        if (value < 0 || value > 0xFFFF_FFFFL) {
            throw new IllegalArgumentException(
                    "Value does not fit an unsigned 32-bit field."
            );
        }

        output.write((int) value & 0xFF);
        output.write((int) (value >>> 8) & 0xFF);
        output.write((int) (value >>> 16) & 0xFF);
        output.write((int) (value >>> 24) & 0xFF);
    }

    private void writeI64LittleEndian(
            ByteArrayOutputStream output,
            long value
    ) {
        byte[] encoded = ByteBuffer
                .allocate(Long.BYTES)
                .order(ByteOrder.LITTLE_ENDIAN)
                .putLong(value)
                .array();

        output.writeBytes(encoded);
    }

    private void requireLength(
            byte[] value,
            int expectedLength,
            String fieldName
    ) {
        if (value == null) {
            throw new IllegalArgumentException(
                    fieldName + " is required."
            );
        }

        if (value.length != expectedLength) {
            throw new IllegalArgumentException(
                    fieldName
                            + " must contain exactly "
                            + expectedLength
                            + " bytes."
            );
        }
    }
}
