package kakha.kudava.fdclient.service;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class VirtualDriveServiceTest {
    @Test
    void acceptsConfirmedDriveLetter() {
        assertEquals("F:", VirtualDriveService.parseMountResponse("MOUNTED F:"));
        assertEquals("Z:", VirtualDriveService.parseMountResponse("MOUNTED Z:"));
    }

    @Test
    void rejectsMissingOrMalformedReadyResponse() {
        assertThrows(IllegalStateException.class, () -> VirtualDriveService.parseMountResponse(null));
        assertThrows(IllegalStateException.class, () -> VirtualDriveService.parseMountResponse("MOUNTED C:"));
        assertThrows(IllegalStateException.class, () -> VirtualDriveService.parseMountResponse("F:"));
    }

    @Test
    void preservesHelpfulNativeFailure() {
        var error = assertThrows(IllegalStateException.class,
                () -> VirtualDriveService.parseMountResponse("ERROR WinFsp is unavailable"));
        assertEquals("ERROR WinFsp is unavailable", error.getMessage());
    }
}
