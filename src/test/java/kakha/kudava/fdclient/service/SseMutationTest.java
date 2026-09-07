package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.SocketException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class SseMutationTest {
    @TempDir Path staging;
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void moveToRootResolvesRealFolderId() throws Exception {
        try (var backend = new Backend(
                new Reply(200, "{\"id\":10,\"folders\":[],\"files\":[{\"id\":7,\"fileName\":\"report.txt\"}]}"),
                new Reply(200, "{\"id\":42,\"folders\":[],\"files\":[]}"), new Reply(204, ""))) {
            execute(backend, """
                    {"op":"relocate","id":7,"directory":false,"parent":0,"sourceParent":10,
                     "name":"report.txt","oldName":"report.txt"}
                    """);
            assertEquals("GET /api/folders/root HTTP/1.1", backend.requests.get(1).line());
            assertEquals("PUT /api/files/7/move HTTP/1.1", backend.requests.get(2).line());
            assertEquals(42, json.readTree(backend.requests.get(2).body()).path("targetFolderId").asLong());
        }
    }

    @Test
    void namesNewFolderAndAllowsCaseOnlyRename() throws Exception {
        try (var backend = new Backend(new Reply(200,
                "{\"id\":42,\"folders\":[{\"id\":7,\"name\":\"New folder\"}],\"files\":[]}"), new Reply(204, ""))) {
            execute(backend, """
                    {"op":"relocate","id":7,"directory":true,"parent":0,"sourceParent":0,
                     "name":"NEW FOLDER","oldName":"New folder"}
                    """);
            assertEquals("PUT /api/folders/7/rename HTTP/1.1", backend.requests.get(1).line());
            assertEquals("NEW FOLDER", json.readTree(backend.requests.get(1).body()).path("newName").asText());
        }
    }

    @Test
    void deletesToTrashWithCorrectEntityType() throws Exception {
        try (var backend = new Backend(new Reply(204, ""))) {
            execute(backend, "{\"op\":\"delete\",\"id\":7,\"directory\":false}");
            assertEquals("POST /api/trashcan/move HTTP/1.1", backend.requests.getFirst().line());
            var body = json.readTree(backend.requests.getFirst().body());
            assertEquals(7, body.path("fileIds").get(0).asLong());
            assertTrue(body.path("folderIds").isEmpty());
        }
        try (var backend = new Backend(new Reply(200, "{\"folders\":[],\"files\":[]}"), new Reply(204, ""))) {
            execute(backend, "{\"op\":\"delete\",\"id\":7,\"directory\":true}");
            var body = json.readTree(backend.requests.get(1).body());
            assertEquals(7, body.path("folderIds").get(0).asLong());
            assertTrue(body.path("fileIds").isEmpty());
        }
    }

    @Test
    void doesNotDeleteUnseenChildrenOrRetryFailedMutations() throws Exception {
        try (var backend = new Backend(new Reply(200, "{\"folders\":[],\"files\":[{\"id\":8,\"deleted\":false}]}"))) {
            assertThrows(IllegalStateException.class, () -> execute(backend, "{\"op\":\"delete\",\"id\":7,\"directory\":true}"));
            assertEquals(1, backend.requests.size());
        }
        try (var backend = new Backend(new Reply(500, ""))) {
            assertThrows(IllegalStateException.class, () -> execute(backend, "{\"op\":\"delete\",\"id\":7,\"directory\":false}"));
            assertEquals(1, backend.requests.size());
        }
    }

    @Test
    void crossTypeCollisionsAreNotExcludedByMatchingId() throws Exception {
        var folder = json.readTree("{\"folders\":[{\"id\":7,\"name\":\"Docs\"}],\"files\":[{\"id\":7,\"fileName\":\"report.txt\"}]}");
        assertThrows(IllegalStateException.class, () -> SseTransferService.ensureAvailable(folder, "report.txt", 7, true));
        assertThrows(IllegalStateException.class, () -> SseTransferService.ensureAvailable(folder, "Docs", 7, false));
    }

    private void execute(Backend backend, String command) throws Exception {
        new SseTransferService(staging, backend::uri).execute(json.readTree(command), "test-token", () -> true);
    }

    private record Reply(int status, String body) {}
    private record Request(String line, String body) {}

    /** Real HTTP on loopback, with no dependency on or changes to a live backend. */
    private static final class Backend implements AutoCloseable {
        final ServerSocket server;
        final Thread worker;
        final List<Request> requests = Collections.synchronizedList(new ArrayList<>());
        volatile Throwable failure;

        Backend(Reply... replies) throws IOException {
            server = new ServerSocket(0, 5, java.net.InetAddress.getLoopbackAddress());
            server.setSoTimeout(5000);
            worker = Thread.ofPlatform().daemon().start(() -> {
                try {
                    for (Reply reply : replies) {
                        try (var socket = server.accept()) {
                            socket.setSoTimeout(5000);
                            var input = socket.getInputStream();
                            var header = new java.io.ByteArrayOutputStream();
                            int state = 0;
                            while (state != 4) {
                                int value = input.read();
                                if (value < 0) throw new IOException("Unexpected HTTP EOF");
                                header.write(value);
                                int expected = state % 2 == 0 ? '\r' : '\n';
                                state = value == expected ? state + 1 : (value == '\r' ? 1 : 0);
                            }
                            String headers = header.toString(StandardCharsets.US_ASCII);
                            int length = 0;
                            for (String line : headers.split("\r\n")) {
                                if (line.toLowerCase().startsWith("content-length:")) length = Integer.parseInt(line.substring(15).trim());
                            }
                            requests.add(new Request(headers.substring(0, headers.indexOf("\r\n")),
                                    new String(input.readNBytes(length), StandardCharsets.UTF_8)));
                            byte[] body = reply.body().getBytes(StandardCharsets.UTF_8);
                            var output = socket.getOutputStream();
                            output.write(("HTTP/1.1 " + reply.status() + " Response\r\nContent-Length: " + body.length
                                    + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                            output.write(body);
                            output.flush();
                        }
                    }
                } catch (SocketException error) { if (!server.isClosed()) failure = error; }
                catch (Throwable error) { failure = error; }
            });
        }

        URI uri(String path) { return URI.create("http://localhost:" + server.getLocalPort() + path); }
        public void close() throws Exception {
            server.close();
            worker.join(1000);
            assertNull(failure, "Mock backend failed: " + failure);
        }
    }
}
