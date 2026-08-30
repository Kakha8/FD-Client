package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/** Builds a metadata-only snapshot using the regular (SSE), not Lockbox, API. */
public final class SseMetadataService {
    private final ObjectMapper json = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();

    public String snapshot(AuthService auth) throws Exception {
        if (!auth.isAuthenticated()) throw new IllegalStateException("Log in to list SSE files.");
        long account = auth.getUserId();
        List<Entry> entries = new ArrayList<>();
        Set<Long> visited = new HashSet<>();
        Set<String> paths = new HashSet<>();
        ArrayDeque<Folder> pending = new ArrayDeque<>();
        pending.add(new Folder("root", ""));
        while (!pending.isEmpty()) {
            if (!auth.isAuthenticated() || auth.getUserId() != account) {
                throw new IllegalStateException("The account changed while listing SSE files.");
            }
            Folder folder = pending.removeFirst();
            JsonNode view = get(folder.id(), auth, true);
            long id = view.path("id").asLong(-1);
            if (id < 1 || !visited.add(id)) throw new IllegalStateException("Invalid or repeated SSE folder ID.");
            if (visited.size() > 10000) throw new IllegalStateException("SSE listing exceeds 10,000 folders.");
            for (Entry entry : parseFolder(view, folder.path())) {
                if (!paths.add(entry.path().toLowerCase(Locale.ROOT))) {
                    throw new IllegalStateException("SSE names collide on Windows: " + entry.path());
                }
                entries.add(entry);
                if (entries.size() > 100000) throw new IllegalStateException("SSE listing exceeds 100,000 items.");
                if (entry.directory()) pending.add(new Folder(Long.toString(entry.id()), entry.path()));
            }
        }
        return encodeSnapshot(entries);
    }

    static String encodeSnapshot(List<Entry> entries) {
        // Explicit JSON avoids reflective access across the application's JPMS boundary.
        var root = new ObjectMapper().createObjectNode();
        var array = root.putArray("entries");
        for (Entry entry : entries) {
            array.addObject().put("id", entry.id()).put("path", entry.path())
                    .put("directory", entry.directory()).put("size", entry.size())
                    .put("created", entry.created()).put("modified", entry.modified());
        }
        return root.toString();
    }

    private JsonNode get(String folder, AuthService auth, boolean retry) throws Exception {
        var request = HttpRequest.newBuilder(BackendConfig.uri("/api/folders/" + folder))
                .timeout(Duration.ofSeconds(30)).header("Accept", "application/json")
                .header("Authorization", "Bearer " + auth.getAccessToken()).GET().build();
        var response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() == 401 && retry) {
            auth.refresh().join();
            return get(folder, auth, false);
        }
        if (response.statusCode() != 200) {
            throw new IllegalStateException("SSE folder listing failed: HTTP " + response.statusCode());
        }
        return json.readTree(response.body());
    }

    static List<Entry> parseFolder(JsonNode view, String parent) {
        if (!view.path("folders").isArray() || !view.path("files").isArray()) {
            throw new IllegalStateException("Invalid SSE folder response.");
        }
        List<Entry> result = new ArrayList<>();
        for (JsonNode item : view.path("folders")) {
            result.add(entry(item, parent, true));
        }
        for (JsonNode item : view.path("files")) {
            if (!item.path("deleted").asBoolean(false)) result.add(entry(item, parent, false));
        }
        return result;
    }

    private static Entry entry(JsonNode item, String parent, boolean directory) {
        long id = item.path("id").asLong(-1);
        String name = item.path(directory ? "name" : "fileName").asText("");
        validateName(name);
        long size = directory ? 0 : item.path("size").asLong(-1);
        if (id < 1 || size < 0) throw new IllegalStateException("Invalid SSE item ID or size.");
        return new Entry(id, parent + "\\" + name, directory, size,
                timestamp(item.path("creationDate")), timestamp(item.path("lastModifiedDate")));
    }

    static void validateName(String name) {
        String base = name.split("\\.", 2)[0].toUpperCase(Locale.ROOT);
        if (name.isBlank() || name.length() > 255 || name.endsWith(".") || name.endsWith(" ")
                || name.chars().anyMatch(c -> c < 32 || "\\/:*?\"<>|".indexOf(c) >= 0)
                || base.matches("CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]")) {
            throw new IllegalStateException("SSE name cannot be represented on Windows: " + name);
        }
    }

    private static long timestamp(JsonNode value) {
        return value.isTextual() ? Instant.parse(value.asText()).toEpochMilli() : 0;
    }

    record Folder(String id, String path) {}
    public record Entry(long id, String path, boolean directory, long size, long created, long modified) {}
}
