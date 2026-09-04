package kakha.kudava.fdclient.service;

import org.junit.jupiter.api.Test;
import java.time.Instant;
import static org.junit.jupiter.api.Assertions.*;

class TotpEnrollmentServiceTest {
    private static final String SEED = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    @Test void firstEnrollmentUsesBackendFieldsWithoutOwnerId() {
        var body = TotpEnrollmentService.beginBody(" Desk ESP32 ", SEED, "test-password", null, null);
        assertEquals("Desk ESP32", body.path("displayName").asText());
        assertEquals(SEED, body.path("secretBase32").asText());
        assertTrue(body.path("existingDeviceId").isNull());
        assertTrue(body.path("existingCode").isNull());
        assertFalse(body.has("userId"));
    }

    @Test void additionalDevicePreservesLeadingZeroCode() {
        var body = TotpEnrollmentService.beginBody("ESP32", SEED, "password", 17L, "012345");
        assertEquals(17, body.path("existingDeviceId").asLong());
        assertEquals("012345", body.path("existingCode").asText());
        assertThrows(TotpEnrollmentService.EnrollmentException.class,
                () -> TotpEnrollmentService.beginBody("ESP32", SEED, "password", 17L, "12345"));
    }

    @Test void rejectsBadSeedWithoutDisclosingIt() {
        var error = assertThrows(TotpEnrollmentService.EnrollmentException.class,
                () -> TotpEnrollmentService.beginBody("ESP32", "secret-test-value", "password", null, null));
        assertFalse(error.getMessage().contains("secret-test-value"));
    }

    @Test void parsesPendingAndRejectsExpiredOrInvalidIds() {
        String json = "{\"deviceId\":12,\"displayName\":\"ESP32\",\"expiresAt\":\""
                + Instant.now().plusSeconds(300) + "\"}";
        assertEquals(12, TotpEnrollmentService.parsePending(json).deviceId());
        assertThrows(TotpEnrollmentService.EnrollmentException.class,
                () -> TotpEnrollmentService.parsePending(json.replace(":12", ":-1")));
        assertThrows(TotpEnrollmentService.EnrollmentException.class,
                () -> TotpEnrollmentService.parsePending("{\"deviceId\":12,\"displayName\":\"ESP32\",\"expiresAt\":\"2000-01-01T00:00:00Z\"}"));
    }

    @Test void confirmationMustMatchPendingDevice() {
        String json = "{\"deviceId\":12,\"confirmedAt\":\"2026-08-31T00:00:00Z\"}";
        assertDoesNotThrow(() -> TotpEnrollmentService.validateConfirmation(json, 12));
        assertThrows(TotpEnrollmentService.EnrollmentException.class,
                () -> TotpEnrollmentService.validateConfirmation(json, 13));
    }

    @Test void disabledAndRateLimitedEnrollmentAreNotSuccess() {
        assertThrows(TotpEnrollmentService.EnrollmentException.class, () -> TotpEnrollmentService.requireStatus(503, 201));
        assertThrows(TotpEnrollmentService.EnrollmentException.class, () -> TotpEnrollmentService.requireStatus(429, 200));
    }
}
