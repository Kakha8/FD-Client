package kakha.kudava.fdclient.service;

import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LockboxRecipientKeyServiceTest {

    private static final UUID RECIPIENT_UUID = UUID.fromString(
            "a33b2748-e1f8-44de-a9c4-a67ca51fa882"
    );

    @Test
    void parsesAndValidatesRecipientKeys() {
        byte[] keyId = bytes(32, 3);
        byte[] publicKey = bytes(1_568, 7);

        LockboxRecipientKeys result =
                LockboxRecipientKeyService.parseResponse(
                        response(
                                RECIPIENT_UUID.toString(),
                                "gela",
                                "ML_KEM_1024",
                                encode(keyId),
                                encode(publicKey)
                        ),
                        "gela"
                );

        assertEquals(2, result.recipientId());
        assertEquals(RECIPIENT_UUID, result.recipientPublicUuid());
        assertEquals("gela", result.username());
        assertEquals(1, result.encryptionKeys().size());
        assertArrayEquals(keyId, result.primaryEncryptionKey().keyId());
        assertArrayEquals(
                publicKey,
                result.primaryEncryptionKey().publicKey()
        );
    }

    @Test
    void returnedBinaryValuesAreDefensiveCopies() {
        LockboxRecipientEncryptionKey key =
                LockboxRecipientKeyService.parseResponse(
                        response(
                                RECIPIENT_UUID.toString(),
                                "gela",
                                "ML_KEM_1024",
                                encode(bytes(32, 1)),
                                encode(bytes(1_568, 2))
                        ),
                        "gela"
                ).primaryEncryptionKey();

        assertNotSame(key.keyId(), key.keyId());
        assertNotSame(key.publicKey(), key.publicKey());
    }

    @Test
    void rejectsInvalidUuidAndMismatchedUsername() {
        String validKeyId = encode(bytes(32, 1));
        String validPublicKey = encode(bytes(1_568, 2));

        assertInvalid(response(
                "not-a-uuid",
                "gela",
                "ML_KEM_1024",
                validKeyId,
                validPublicKey
        ), "gela");

        assertInvalid(response(
                RECIPIENT_UUID.toString(),
                "someone-else",
                "ML_KEM_1024",
                validKeyId,
                validPublicKey
        ), "gela");
    }

    @Test
    void rejectsUnsupportedAlgorithmAndMalformedBase64() {
        String validKeyId = encode(bytes(32, 1));
        String validPublicKey = encode(bytes(1_568, 2));

        assertInvalid(response(
                RECIPIENT_UUID.toString(),
                "gela",
                "ML_KEM_768",
                validKeyId,
                validPublicKey
        ), "gela");

        assertInvalid(response(
                RECIPIENT_UUID.toString(),
                "gela",
                "ML_KEM_1024",
                "%%%",
                validPublicKey
        ), "gela");
    }

    @Test
    void rejectsIncorrectKeyLengthsAndEmptyKeyList() {
        assertInvalid(response(
                RECIPIENT_UUID.toString(),
                "gela",
                "ML_KEM_1024",
                encode(bytes(31, 1)),
                encode(bytes(1_568, 2))
        ), "gela");

        assertInvalid(response(
                RECIPIENT_UUID.toString(),
                "gela",
                "ML_KEM_1024",
                encode(bytes(32, 1)),
                encode(bytes(1_567, 2))
        ), "gela");

        assertInvalid(
                "{\"recipientId\":2,"
                        + "\"recipientPublicUuid\":\"" + RECIPIENT_UUID + "\","
                        + "\"username\":\"gela\","
                        + "\"encryptionKeys\":[]}",
                "gela"
        );
    }

    private static void assertInvalid(
            String body,
            String requestedUsername
    ) {
        assertThrows(
                LockboxRecipientKeyService.RecipientKeyException.class,
                () -> LockboxRecipientKeyService.parseResponse(
                        body,
                        requestedUsername
                )
        );
    }

    private static String response(
            String recipientUuid,
            String username,
            String algorithm,
            String keyId,
            String publicKey
    ) {
        return "{"
                + "\"recipientId\":2,"
                + "\"recipientPublicUuid\":\"" + recipientUuid + "\","
                + "\"username\":\"" + username + "\","
                + "\"encryptionKeys\":[{"
                + "\"keyId\":\"" + keyId + "\","
                + "\"algorithm\":\"" + algorithm + "\","
                + "\"publicKey\":\"" + publicKey + "\""
                + "}]}";
    }

    private static String encode(
            byte[] value
    ) {
        return Base64.getEncoder().encodeToString(value);
    }

    private static byte[] bytes(
            int length,
            int seed
    ) {
        byte[] value = new byte[length];

        for (int index = 0; index < value.length; index++) {
            value[index] = (byte) (seed + index);
        }

        return value;
    }
}
