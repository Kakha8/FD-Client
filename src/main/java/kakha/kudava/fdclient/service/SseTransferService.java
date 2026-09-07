package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.UUID;
import java.util.function.BooleanSupplier;

/** HTTP stays in Java; the helper only sees metadata and private staging filenames. */
final class SseTransferService {
    private final ObjectMapper json = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    private final Path staging;
    private final java.util.function.Function<String, java.net.URI> endpoint;

    SseTransferService(Path staging) { this(staging, BackendConfig::uri); }

    SseTransferService(Path staging, java.util.function.Function<String, java.net.URI> endpoint) {
        this.staging = staging;
        this.endpoint = endpoint;
    }

    ObjectNode execute(JsonNode command, String token, BooleanSupplier active) throws Exception {
        check(active);
        ObjectNode result = json.createObjectNode().put("ok", true);
        String operation = command.path("op").asText();
        switch (operation) {
            case "relocate" -> {
                long id = positiveId(command, "id");
                boolean directory = command.path("directory").asBoolean();
                long parent = command.path("parent").asLong(-1);
                long sourceParent = command.path("sourceParent").asLong(-1);
                if (parent < 0 || sourceParent < 0) throw new IllegalArgumentException("Invalid parent folder.");
                String name = command.path("name").asText();
                SseMetadataService.validateName(name);
                JsonNode source = getJson(folderEndpoint(sourceParent), token, active);
                JsonNode item = findItem(source, id, directory);
                String oldName = item.path(directory ? "name" : "fileName").asText();
                if (!oldName.equals(command.path("oldName").asText())) {
                    throw new IllegalStateException("The item changed on the server. Refresh the drive and retry.");
                }
                boolean moving = parent != sourceParent;
                if (moving && !name.equals(oldName)) {
                    throw new IllegalArgumentException("Move and rename the item in separate steps.");
                }
                JsonNode destination = moving ? getJson(folderEndpoint(parent), token, active) : source;
                ensureAvailable(destination, name, moving ? -1 : id, directory);
                String endpoint = "/api/" + (directory ? "folders/" : "files/") + id;
                ObjectNode body = json.createObjectNode();
                if (moving) {
                    long targetId = destination.path("id").asLong();
                    if (targetId <= 0) throw new IllegalStateException("Invalid destination folder ID.");
                    body.put("targetFolderId", targetId);
                    endpoint += "/move";
                } else {
                    if (name.equals(oldName)) return result;
                    body.put("newName", name);
                    endpoint += "/rename";
                }
                sendMutation(endpoint, "PUT", body, token, active);
            }
            case "delete" -> {
                long id = positiveId(command, "id");
                boolean directory = command.path("directory").asBoolean();
                if (directory) {
                    // Windows recursively removes children first. Do not trash new
                    // server-side children that were absent from the Explorer scan.
                    JsonNode folder = getJson("/api/folders/" + id, token, active);
                    if (!folder.path("folders").isArray() || !folder.path("files").isArray()) {
                        throw new IllegalStateException("Invalid folder response.");
                    }
                    if (!folder.path("folders").isEmpty()) throw new IllegalStateException("The folder is not empty. Refresh and retry.");
                    for (JsonNode file : folder.path("files")) {
                        if (!file.path("deleted").asBoolean()) throw new IllegalStateException("The folder is not empty. Refresh and retry.");
                    }
                }
                ObjectNode body = json.createObjectNode();
                body.putArray("fileIds");
                body.putArray("folderIds");
                ((com.fasterxml.jackson.databind.node.ArrayNode) body.get(directory ? "folderIds" : "fileIds")).add(id);
                sendMutation("/api/trashcan/move", "POST", body, token, active);
            }
            case "upload_failed" -> throw new IllegalStateException("Writing the local staging file failed. The upload was not sent.");
            case "download" -> {
                long id = command.path("id").asLong();
                if (id <= 0) throw new IllegalArgumentException("Invalid download ID.");
                Path target = Files.createTempFile(staging, "download-", ".part");
                try {
                    var response = http.send(request("/api/files/" + id, token).GET().build(),
                            HttpResponse.BodyHandlers.ofFile(target, java.nio.file.StandardOpenOption.WRITE,
                                    java.nio.file.StandardOpenOption.TRUNCATE_EXISTING));
                    if (response.statusCode() != 200) throw failure(response.statusCode());
                    check(active);
                    result.put("file", target.getFileName().toString());
                } catch (Exception error) {
                    Files.deleteIfExists(target);
                    throw error;
                }
            }
            case "ready", "upload", "mkdir" -> {
                String name = command.path("name").asText();
                SseMetadataService.validateName(name);
                long parent = command.path("parent").asLong(-1);
                if (parent < 0) throw new IllegalArgumentException("Invalid parent folder.");
                String folderEndpoint = "/api/folders/" + (parent == 0 ? "root" : parent);
                JsonNode folder = getJson(folderEndpoint, token, active);
                ensureAvailable(folder, name);
                check(active);
                if (operation.equals("ready")) return result;
                if (operation.equals("mkdir")) {
                    ObjectNode body = json.createObjectNode().put("name", name);
                    if (parent != 0) body.put("parentId", parent);
                    var response = http.send(request("/api/folders", token)
                                    .header("Content-Type", "application/json")
                                    .POST(HttpRequest.BodyPublishers.ofString(body.toString())).build(),
                            HttpResponse.BodyHandlers.ofString());
                    if (response.statusCode() != 201) throw failure(response.statusCode());
                    JsonNode updated = getJson(folderEndpoint, token, active);
                    long id = 0;
                    for (JsonNode item : updated.path("folders")) {
                        if (item.path("name").asText().equals(name)) {
                            if (id != 0) throw new IllegalStateException("Ambiguous folder name after creation.");
                            id = item.path("id").asLong();
                        }
                    }
                    if (id <= 0) throw new IllegalStateException("Created folder could not be resolved.");
                    result.put("id", id);
                } else {
                    Path file = uploadPath(command.path("file").asText());
                    String boundary = "FDDrive" + UUID.randomUUID().toString().replace("-", "");
                    String prefix = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\""
                            + name + "\"\r\nContent-Type: application/octet-stream\r\n\r\n";
                    var publisher = HttpRequest.BodyPublishers.concat(
                            HttpRequest.BodyPublishers.ofByteArray(prefix.getBytes(StandardCharsets.UTF_8)),
                            HttpRequest.BodyPublishers.ofFile(file),
                            HttpRequest.BodyPublishers.ofString("\r\n--" + boundary + "--\r\n"));
                    var response = http.send(request("/api/files" + (parent == 0 ? "" : "?parentId=" + parent), token)
                                    .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                                    .POST(publisher).build(), HttpResponse.BodyHandlers.ofString());
                    // No automatic retries: a timeout can occur after the server commits the file.
                    if (response.statusCode() != 201) throw failure(response.statusCode());
                    long id = json.readTree(response.body()).path("id").asLong();
                    if (id <= 0) throw new IllegalStateException("Upload response has no file ID.");
                    result.put("id", id);
                }
            }
            default -> throw new IllegalArgumentException("Unknown transfer operation.");
        }
        check(active);
        return result;
    }

    Path uploadPath(String name) {
        if (!name.matches("upload-[0-9]+\\.part")) throw new IllegalArgumentException("Invalid staging filename.");
        return staging.resolve(name);
    }

    void cleanDownloads() {
        try (var files = Files.newDirectoryStream(staging, "download-*.part")) {
            for (Path file : files) {
                try { Files.deleteIfExists(file); } catch (java.io.IOException ignored) { }
            }
        } catch (java.io.IOException ignored) { }
        // This succeeds only when empty; failed upload files are retained.
        try { Files.delete(staging); } catch (java.io.IOException ignored) { }
    }

    static void ensureAvailable(JsonNode folder, String name) {
        ensureAvailable(folder, name, -1, false);
    }

    static void ensureAvailable(JsonNode folder, String name, long excludedId, boolean directory) {
        if (!folder.path("folders").isArray() || !folder.path("files").isArray()) {
            throw new IllegalStateException("Invalid destination folder response.");
        }
        for (JsonNode item : folder.path("folders")) {
            if (directory && item.path("id").asLong(-1) == excludedId && excludedId > 0) continue;
            if (name.equalsIgnoreCase(item.path("name").asText())) throw new IllegalStateException("A folder with this name already exists.");
        }
        for (JsonNode item : folder.path("files")) {
            if (!directory && item.path("id").asLong(-1) == excludedId && excludedId > 0) continue;
            if (!item.path("deleted").asBoolean() && name.equalsIgnoreCase(item.path("fileName").asText())) {
                throw new IllegalStateException("A file with this name already exists.");
            }
        }
    }

    private static long positiveId(JsonNode command, String field) {
        long id = command.path(field).asLong();
        if (id <= 0) throw new IllegalArgumentException("Invalid item ID.");
        return id;
    }

    private static String folderEndpoint(long id) { return "/api/folders/" + (id == 0 ? "root" : id); }

    private static JsonNode findItem(JsonNode folder, long id, boolean directory) {
        for (JsonNode item : folder.path(directory ? "folders" : "files")) {
            if (item.path("id").asLong() == id && !item.path("deleted").asBoolean()) return item;
        }
        throw new IllegalStateException("The source item no longer exists in this folder. Refresh and retry.");
    }

    private void sendMutation(String endpoint, String method, ObjectNode body, String token,
                              BooleanSupplier active) throws Exception {
        check(active);
        var response = http.send(request(endpoint, token).header("Content-Type", "application/json")
                .method(method, HttpRequest.BodyPublishers.ofString(body.toString())).build(),
                HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 204) throw failure(response.statusCode());
        check(active);
    }

    private JsonNode getJson(String endpoint, String token, BooleanSupplier active) throws Exception {
        check(active);
        var response = http.send(request(endpoint, token).GET().build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) throw failure(response.statusCode());
        check(active);
        return json.readTree(response.body());
    }

    private HttpRequest.Builder request(String endpoint, String token) {
        return HttpRequest.newBuilder(this.endpoint.apply(endpoint)).timeout(Duration.ofSeconds(210))
                .header("Authorization", "Bearer " + token);
    }

    private static void check(BooleanSupplier active) {
        if (!active.getAsBoolean()) throw new IllegalStateException("Drive session ended. Transfer cancelled.");
    }

    private static IllegalStateException failure(int status) {
        return new IllegalStateException("SSE transfer failed: HTTP " + status);
    }
}
