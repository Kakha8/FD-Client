package kakha.kudava.fdclient.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

final class LockboxRevisionServiceTest {
    @Test
    void parsesValidHistoryAndIdentifiesCurrentRevision() throws Exception {
        String hash = "a".repeat(128);
        String body = """
                {"fileId":17,"clientFileId":"81d4a89b-5eb9-4f83-b80d-f2483db42041",
                 "currentRevision":2,"revisions":[
                   {"revision":2,"containerSize":200,"containerHash":"%s",
                    "createdAt":"2026-08-27T10:00:00Z","current":true},
                   {"revision":1,"containerSize":100,"containerHash":"%s",
                    "createdAt":"2026-08-26T10:00:00Z","current":false}]}
                """.formatted(hash, hash);

        var history = LockboxRevisionService.parse(body);

        assertEquals(17, history.fileId());
        assertEquals(2, history.currentRevision());
        assertEquals(2, history.revisions().size());
        assertTrue(history.revisions().getFirst().current());
    }

    @Test
    void rejectsHistoryWithoutUniqueCurrentRevision() {
        String hash = "b".repeat(128);
        String body = """
                {"fileId":17,"clientFileId":"81d4a89b-5eb9-4f83-b80d-f2483db42041",
                 "currentRevision":2,"revisions":[
                   {"revision":2,"containerSize":200,"containerHash":"%s",
                    "createdAt":"2026-08-27T10:00:00Z","current":false}]}
                """.formatted(hash);

        assertThrows(IllegalStateException.class,
                () -> LockboxRevisionService.parse(body));
    }
}
