package kakha.kudava.fdclient.service;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class LockboxShareGrantTest {
    @Test
    void validatesLengthsAndDefensivelyCopiesFields() {
        byte[] envelope = new byte[LockboxShareGrant.ENVELOPE_LENGTH];
        byte[] keyId = new byte[LockboxShareGrant.KEY_ID_LENGTH];
        byte[] signature = new byte[LockboxShareGrant.SIGNATURE_LENGTH];
        envelope[0] = 1;
        keyId[0] = 2;
        signature[0] = 3;

        LockboxShareGrant grant = new LockboxShareGrant(envelope, keyId, signature);
        envelope[0] = keyId[0] = signature[0] = 9;

        assertEquals(1, grant.envelope()[0]);
        assertEquals(2, grant.ownerSigningKeyId()[0]);
        assertEquals(3, grant.ownerSignature()[0]);
        byte[] returned = grant.envelope();
        returned[0] = 8;
        assertEquals(1, grant.envelope()[0]);

        assertThrows(IllegalArgumentException.class,
                () -> new LockboxShareGrant(new byte[1], keyId, signature));
        assertThrows(IllegalArgumentException.class,
                () -> new LockboxShareGrant(envelope, new byte[1], signature));
        assertThrows(IllegalArgumentException.class,
                () -> new LockboxShareGrant(envelope, keyId, new byte[1]));
    }

    @Test
    void grantMessageIsExactDomainFollowedByExactEnvelope() {
        byte[] envelope = new byte[LockboxShareGrant.ENVELOPE_LENGTH];
        Arrays.fill(envelope, (byte) 0xA5);

        byte[] message = LockboxShareService.grantMessage(envelope);
        byte[] expectedDomain = "FD-CSE-V3-SHARE-GRANT-V1\0"
                .getBytes(StandardCharsets.US_ASCII);

        assertEquals(25 + LockboxShareGrant.ENVELOPE_LENGTH, message.length);
        assertArrayEquals(expectedDomain, Arrays.copyOf(message, 25));
        assertArrayEquals(envelope, Arrays.copyOfRange(message, 25, message.length));
        envelope[0] = 0;
        assertEquals((byte) 0xA5, message[25]);
        assertThrows(IllegalArgumentException.class,
                () -> LockboxShareService.grantMessage(new byte[1]));
    }

    @Test
    void uuidEncodingUsesCanonicalNetworkByteOrder() {
        UUID uuid = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff");
        assertArrayEquals(new byte[] {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb,
                (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff
        }, LockboxShareService.uuidBytes(uuid));
    }
}
