package kakha.kudava.fdclient.service;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LockboxOwnDeviceServiceTest {
    private static final UUID DEVICE_ID = UUID.fromString(
            "ccbd7bb9-f65c-4713-aafb-004a12a1bd13");

    @Test
    void parsesActiveDeviceAndEncryptionKey() {
        byte[] keyId = bytes(32, 4);
        byte[] publicKey = bytes(1_568, 9);

        var devices = LockboxOwnDeviceService.parseResponse(
                response("ACTIVE", "ML_KEM_1024", encode(keyId), encode(publicKey)));

        assertEquals(1, devices.size());
        LockboxOwnDevice device = devices.getFirst();
        assertEquals(DEVICE_ID, device.deviceId());
        assertEquals("Laptop", device.deviceName());
        assertArrayEquals(keyId, device.primaryEncryptionKey().keyId());
        assertArrayEquals(publicKey, device.primaryEncryptionKey().publicKey());
    }

    @Test
    void rejectsInactiveDeviceAndUnsupportedAlgorithm() {
        String keyId = encode(bytes(32, 1));
        String publicKey = encode(bytes(1_568, 2));

        assertInvalid(response("REVOKED", "ML_KEM_1024", keyId, publicKey));
        assertInvalid(response("ACTIVE", "ML_KEM_768", keyId, publicKey));
    }

    @Test
    void rejectsMalformedOrWrongLengthKeys() {
        assertInvalid(response(
                "ACTIVE", "ML_KEM_1024", "%%%", encode(bytes(1_568, 2))));
        assertInvalid(response(
                "ACTIVE", "ML_KEM_1024", encode(bytes(31, 1)), encode(bytes(1_568, 2))));
        assertInvalid(response(
                "ACTIVE", "ML_KEM_1024", encode(bytes(32, 1)), encode(bytes(1_567, 2))));
    }

    @Test
    void rejectsMissingEncryptionKeys() {
        assertInvalid("{\"devices\":[{\"deviceId\":\"" + DEVICE_ID
                + "\",\"deviceName\":\"Laptop\",\"deviceStatus\":\"ACTIVE\"," 
                + "\"encryptionKeys\":[]}]}");
    }

    private static void assertInvalid(String body) {
        assertThrows(
                LockboxOwnDeviceService.OwnDeviceException.class,
                () -> LockboxOwnDeviceService.parseResponse(body));
    }

    private static String response(
            String status,
            String algorithm,
            String keyId,
            String publicKey
    ) {
        return "{\"devices\":[{"
                + "\"deviceId\":\"" + DEVICE_ID + "\","
                + "\"deviceName\":\"Laptop\","
                + "\"deviceStatus\":\"" + status + "\","
                + "\"encryptionKeys\":[{"
                + "\"keyId\":\"" + keyId + "\","
                + "\"algorithm\":\"" + algorithm + "\","
                + "\"publicKey\":\"" + publicKey + "\"}]}]}";
    }

    private static String encode(byte[] value) {
        return Base64.getEncoder().encodeToString(value);
    }

    private static byte[] bytes(int length, int seed) {
        byte[] result = new byte[length];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte) (seed + index);
        }
        return result;
    }
}
