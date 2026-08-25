package kakha.kudava.fdclient.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

class LockboxInstallationIdentityTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void installationIdPersistsAcrossLoads() {
        Path path = temporaryDirectory.resolve("installation-id");

        UUID first = LockboxInstallationIdentity.loadOrCreate(path);
        UUID second = LockboxInstallationIdentity.loadOrCreate(path);

        assertEquals(first, second);
    }

    @Test
    void handleMatchesCanonicalProtocolFormula() throws Exception {
        UUID installationId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff");
        UUID userPublicUuid = UUID.fromString("fedcba98-7654-3210-ffff-eeeeeeeeeeee");

        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        digest.update("FD-INSTALLATION-HANDLE-V1\0".getBytes(StandardCharsets.US_ASCII));
        digest.update(uuidBytes(installationId));
        digest.update(uuidBytes(userPublicUuid));
        String expected = Base64.getEncoder().encodeToString(digest.digest());

        assertEquals(
                expected,
                LockboxInstallationIdentity.deriveHandle(installationId, userPublicUuid)
        );
    }

    @Test
    void sameInstallationProducesDifferentHandlesForDifferentAccounts() {
        UUID installationId = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff");

        String first = LockboxInstallationIdentity.deriveHandle(
                installationId,
                UUID.fromString("10000000-0000-0000-0000-000000000001")
        );
        String second = LockboxInstallationIdentity.deriveHandle(
                installationId,
                UUID.fromString("10000000-0000-0000-0000-000000000002")
        );

        assertNotEquals(first, second);
        assertEquals(32, Base64.getDecoder().decode(first).length);
        assertEquals(32, Base64.getDecoder().decode(second).length);
    }

    private static byte[] uuidBytes(UUID value) {
        return ByteBuffer.allocate(16)
                .order(ByteOrder.BIG_ENDIAN)
                .putLong(value.getMostSignificantBits())
                .putLong(value.getLeastSignificantBits())
                .array();
    }
}
