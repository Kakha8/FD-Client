package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SseMetadataServiceTest {
    @Test void parsesNestedFilesAndExcludesDeleted() throws Exception {
        var view = new ObjectMapper().readTree("""
                {"folders":[{"id":2,"name":"Docs"}],"files":[
                {"id":3,"fileName":"hello.txt","size":123,"creationDate":"2026-08-30T00:00:00Z"},
                {"id":4,"fileName":"deleted.txt","size":1,"deleted":true}]}
                """);
        var entries = SseMetadataService.parseFolder(view, "\\Parent");
        assertEquals(2, entries.size());
        assertEquals("\\Parent\\Docs", entries.get(0).path());
        assertTrue(entries.get(0).directory());
        assertEquals(123, entries.get(1).size());
        assertTrue(entries.get(1).created() > 0);
        var snapshot = new ObjectMapper().readTree(SseMetadataService.encodeSnapshot(entries));
        assertEquals("\\Parent\\hello.txt", snapshot.path("entries").get(1).path("path").asText());
        assertEquals(123, snapshot.path("entries").get(1).path("size").asLong());
    }

    @Test void rejectsUnsafeWindowsNames() {
        for (String name : new String[]{"..", "a/b", "a\\b", "x:stream", "CON", "NUL.txt", "trailing."}) {
            assertThrows(IllegalStateException.class, () -> SseMetadataService.validateName(name));
        }
        assertDoesNotThrow(() -> SseMetadataService.validateName("ქართული.txt"));
    }

    @Test void rejectsMalformedListing() throws Exception {
        var view = new ObjectMapper().readTree("{}");
        assertThrows(IllegalStateException.class, () -> SseMetadataService.parseFolder(view, ""));
    }
}
