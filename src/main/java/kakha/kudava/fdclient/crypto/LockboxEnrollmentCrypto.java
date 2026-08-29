package kakha.kudava.fdclient.crypto;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

public final class LockboxEnrollmentCrypto {

    private static final byte[] DOMAIN =
            "FD-LOCKBOX-DEVICE-ENROLLMENT-V2\0"
                    .getBytes(StandardCharsets.US_ASCII);

    public EnrollmentProof createProof(
            UUID enrollmentId,
            String encodedChallenge,
            Instant expiresAt,
            UUID deviceId,
            String encodedInstallationHandle,
            String deviceName
    ) {
        byte[] challenge = decodeExact(encodedChallenge, 32, "challenge");
        byte[] installationHandle = decodeExact(
                encodedInstallationHandle,
                32,
                "installation handle"
        );
        byte[] encryptionPublicKey = requireExact(
                NativeCryptoBridge.getStoredMlKem1024PublicKey(),
                1_568,
                "ML-KEM-1024 public key"
        );
        byte[] signingPublicKey = requireExact(
                NativeCryptoBridge.getStoredMlDsa87PublicKey(),
                2_592,
                "ML-DSA-87 public key"
        );
        byte[] encryptionKeyId = sha3(encryptionPublicKey);
        byte[] signingKeyId = sha3(signingPublicKey);
        String normalizedName = normalizeDeviceName(deviceName);

        byte[] transcript = encodeTranscript(
                enrollmentId, challenge, expiresAt, deviceId, installationHandle, normalizedName,
                encryptionKeyId, encryptionPublicKey, signingKeyId, signingPublicKey
        );
        byte[] signature = requireExact(
                NativeCryptoBridge.signWithStoredMlDsa87(transcript),
                4_627,
                "ML-DSA-87 signature"
        );

        Base64.Encoder base64 = Base64.getEncoder();
        return new EnrollmentProof(
                encodedChallenge,
                deviceId,
                encodedInstallationHandle,
                normalizedName,
                base64.encodeToString(encryptionKeyId),
                base64.encodeToString(encryptionPublicKey),
                base64.encodeToString(signingKeyId),
                base64.encodeToString(signingPublicKey),
                base64.encodeToString(signature)
        );
    }

    static byte[] encodeTranscript(
            UUID enrollmentId, byte[] challenge, Instant expiresAt,
            UUID deviceId, byte[] installationHandle, String deviceName,
            byte[] encryptionKeyId, byte[] encryptionPublicKey,
            byte[] signingKeyId, byte[] signingPublicKey
    ) {
        Objects.requireNonNull(enrollmentId, "enrollmentId");
        Objects.requireNonNull(expiresAt, "expiresAt");
        Objects.requireNonNull(deviceId, "deviceId");
        requireExact(challenge, 32, "challenge");
        requireExact(installationHandle, 32, "installation handle");
        requireExact(encryptionKeyId, 32, "encryption key ID");
        requireExact(encryptionPublicKey, 1_568, "encryption public key");
        requireExact(signingKeyId, 32, "signing key ID");
        requireExact(signingPublicKey, 2_592, "signing public key");

        byte[] name = normalizeDeviceName(deviceName).getBytes(StandardCharsets.UTF_8);
        if (name.length > 255) {
            throw new IllegalArgumentException("Device name exceeds 255 UTF-8 bytes.");
        }

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(DOMAIN);
        out.writeBytes(uuidBytes(enrollmentId));
        out.writeBytes(challenge);
        out.writeBytes(littleEndianLong(expiresAt.toEpochMilli()));
        out.writeBytes(uuidBytes(deviceId));
        out.writeBytes(installationHandle);
        writeU16(out, name.length);
        out.writeBytes(name);
        writeU16(out, 1);
        out.writeBytes(encryptionKeyId);
        writeU32(out, encryptionPublicKey.length);
        out.writeBytes(encryptionPublicKey);
        writeU16(out, 1);
        out.writeBytes(signingKeyId);
        writeU32(out, signingPublicKey.length);
        out.writeBytes(signingPublicKey);
        return out.toByteArray();
    }

    private static String normalizeDeviceName(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Device name is required.");
        }
        String normalized = value.trim();
        if (normalized.length() > 100) {
            throw new IllegalArgumentException("Device name exceeds 100 characters.");
        }
        return normalized;
    }

    private static byte[] uuidBytes(UUID uuid) {
        return ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits()).array();
    }

    private static byte[] littleEndianLong(long value) {
        return ByteBuffer.allocate(Long.BYTES).order(ByteOrder.LITTLE_ENDIAN)
                .putLong(value).array();
    }

    private static void writeU16(ByteArrayOutputStream out, int value) {
        out.write(value & 0xff);
        out.write((value >>> 8) & 0xff);
    }

    private static void writeU32(ByteArrayOutputStream out, int value) {
        out.write(value & 0xff);
        out.write((value >>> 8) & 0xff);
        out.write((value >>> 16) & 0xff);
        out.write((value >>> 24) & 0xff);
    }

    private static byte[] sha3(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA3-256").digest(value);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA3-256 is unavailable.", e);
        }
    }

    private static byte[] decodeExact(String value, int length, String name) {
        try {
            return requireExact(Base64.getDecoder().decode(value), length, name);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(name + " is invalid.", e);
        }
    }

    private static byte[] requireExact(byte[] value, int length, String name) {
        if (value == null || value.length != length) {
            throw new IllegalStateException(name + " must contain exactly " + length + " bytes.");
        }
        return value;
    }

    public record EnrollmentProof(
            String challenge,
            UUID deviceId,
            String installationHandle,
            String deviceName,
            String encryptionKeyId,
            String encryptionPublicKey,
            String signingKeyId,
            String signingPublicKey,
            String signature
    ) {}
}
