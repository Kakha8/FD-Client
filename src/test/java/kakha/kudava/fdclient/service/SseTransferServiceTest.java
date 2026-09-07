package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.junit.jupiter.api.Assertions.*;

class SseTransferServiceTest {
    @TempDir Path staging;
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void rejectsWindowsCollisionsBeforeUpload() throws Exception {
        var folder = json.readTree("""
                {"folders":[{"name":"Docs"}],"files":[
                  {"fileName":"Report.txt","deleted":false},
                  {"fileName":"Old.txt","deleted":true}]}
                """);
        assertThrows(IllegalStateException.class, () -> SseTransferService.ensureAvailable(folder, "docs"));
        assertThrows(IllegalStateException.class, () -> SseTransferService.ensureAvailable(folder, "REPORT.TXT"));
        assertDoesNotThrow(() -> SseTransferService.ensureAvailable(folder, "Old.txt"));
        assertThrows(IllegalStateException.class, () -> SseTransferService.ensureAvailable(json.createObjectNode(), "new"));
    }

    @Test
    void helperCannotUploadArbitraryLocalPaths() {
        var service = new SseTransferService(staging);
        assertEquals(staging.resolve("upload-12.part"), service.uploadPath("upload-12.part"));
        for (String name : new String[]{"../secret", "C:\\secret", "upload-1.part/secret", "download-1.part"}) {
            assertThrows(IllegalArgumentException.class, () -> service.uploadPath(name));
        }
    }

    @Test
    void endedSessionDoesNotStartATransfer() throws Exception {
        var service = new SseTransferService(staging);
        var request = json.readTree("{\"op\":\"download\",\"id\":1}");
        assertThrows(IllegalStateException.class, () -> service.execute(request, "test-token", () -> false));
        try (var files = Files.list(staging)) { assertEquals(0, files.count()); }
    }

    @Test
    void shutdownRemovesDownloadsButRetainsFailedUploadsAndTheirNames() throws Exception {
        Files.writeString(staging.resolve("download-1.part"), "download");
        Files.writeString(staging.resolve("upload-1.part"), "recover me");
        Files.writeString(staging.resolve("upload-1.name.txt"), "\\Docs\\report.txt");
        new SseTransferService(staging).cleanDownloads();
        assertFalse(Files.exists(staging.resolve("download-1.part")));
        assertEquals("recover me", Files.readString(staging.resolve("upload-1.part")));
        assertEquals("\\Docs\\report.txt", Files.readString(staging.resolve("upload-1.name.txt")));
    }
}
