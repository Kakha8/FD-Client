package kakha.kudava.fdclient.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

final class LockboxPreviousShareServiceTest {
    @Test
    void parsesUserAndDeviceTargetedShares() throws Exception {
        var shares = LockboxPreviousShareService.parse("""
                {"shares":[
                  {"recipientUsername":"alice","targetDeviceId":null,"expiresAtUnixSeconds":0},
                  {"recipientUsername":"owner","targetDeviceId":"81d4a89b-5eb9-4f83-b80d-f2483db42041",
                   "expiresAtUnixSeconds":1900000000}]}
                """);

        assertEquals(2, shares.size());
        assertFalse(shares.getFirst().deviceTargeted());
        assertTrue(shares.get(1).deviceTargeted());
        assertEquals(1_900_000_000L, shares.get(1).expiresAtUnixSeconds());
    }

    @Test
    void rejectsMalformedShareEntries() {
        assertThrows(IllegalStateException.class,
                () -> LockboxPreviousShareService.parse(
                        "{\"shares\":[{\"recipientUsername\":\"\"}]}"));
    }
}
