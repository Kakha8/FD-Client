package kakha.kudava.fdclient.crypto;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class LockboxEnrollmentCryptoTest {

    @Test
    void transcriptMatchesBackendFieldOrderAndEndianness() {
        UUID enrollmentId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff");
        UUID deviceId = UUID.fromString("fedcba98-7654-3210-ffff-eeeeeeeeeeee");
        byte[] challenge = filled(32, (byte) 0x11);
        byte[] installationHandle = filled(32, (byte) 0x66);
        byte[] encryptionKeyId = filled(32, (byte) 0x22);
        byte[] encryptionPublicKey = filled(1_568, (byte) 0x33);
        byte[] signingKeyId = filled(32, (byte) 0x44);
        byte[] signingPublicKey = filled(2_592, (byte) 0x55);

        byte[] transcript = LockboxEnrollmentCrypto.encodeTranscript(
                enrollmentId, challenge, Instant.ofEpochMilli(0x0102030405060708L),
                deviceId, installationHandle, " Test Device ", encryptionKeyId, encryptionPublicKey,
                signingKeyId, signingPublicKey
        );

        byte[] domain = "FD-LOCKBOX-DEVICE-ENROLLMENT-V2\0"
                .getBytes(StandardCharsets.US_ASCII);
        int offset = 0;
        assertArrayEquals(domain, Arrays.copyOfRange(transcript, offset, offset += domain.length));
        assertArrayEquals(uuidBytes(enrollmentId), Arrays.copyOfRange(transcript, offset, offset += 16));
        assertArrayEquals(challenge, Arrays.copyOfRange(transcript, offset, offset += 32));
        assertArrayEquals(new byte[]{8, 7, 6, 5, 4, 3, 2, 1},
                Arrays.copyOfRange(transcript, offset, offset += 8));
        assertArrayEquals(uuidBytes(deviceId), Arrays.copyOfRange(transcript, offset, offset += 16));
        assertArrayEquals(installationHandle,
                Arrays.copyOfRange(transcript, offset, offset += 32));
        assertArrayEquals(new byte[]{11, 0}, Arrays.copyOfRange(transcript, offset, offset += 2));
        assertArrayEquals("Test Device".getBytes(StandardCharsets.UTF_8),
                Arrays.copyOfRange(transcript, offset, offset += 11));
        assertArrayEquals(new byte[]{1, 0}, Arrays.copyOfRange(transcript, offset, offset += 2));
        offset += 32;
        assertArrayEquals(new byte[]{0x20, 0x06, 0, 0},
                Arrays.copyOfRange(transcript, offset, offset += 4));
        offset += 1_568;
        assertArrayEquals(new byte[]{1, 0}, Arrays.copyOfRange(transcript, offset, offset += 2));
        offset += 32;
        assertArrayEquals(new byte[]{0x20, 0x0A, 0, 0},
                Arrays.copyOfRange(transcript, offset, offset += 4));
        offset += 2_592;
        assertEquals(transcript.length, offset);
    }

    private static byte[] filled(int length, byte value) {
        byte[] bytes = new byte[length];
        Arrays.fill(bytes, value);
        return bytes;
    }

    private static byte[] uuidBytes(UUID uuid) {
        return ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN)
                .putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits()).array();
    }
}
