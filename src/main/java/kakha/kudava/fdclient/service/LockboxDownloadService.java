package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import kakha.kudava.fdclient.crypto.NativeCryptoBridge;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public final class LockboxDownloadService {
    private static final URI BASE = URI.create("https://localhost:8443/api/lockbox/files/");
    private static final int MANIFEST_LENGTH = 264;
    private static final int SIGNATURE_LENGTH = 4_675;
    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15)).build();

    public CompletableFuture<Void> download(
            LockboxMetadataService.PrivateFile file,
            String accessToken
    ) {
        return CompletableFuture.runAsync(() -> downloadBlocking(file, accessToken));
    }

    private void downloadBlocking(LockboxMetadataService.PrivateFile file, String token) {
        if (file == null || file.serverId() == null) {
            throw new IllegalArgumentException("A web Lockbox file is required.");
        }
        if (token == null || token.isBlank()) {
            throw new IllegalStateException("No authenticated session is available.");
        }

        Path directory = new CseEncryptionService().artifactDirectory();
        String base = file.clientFileId().toString();
        Path manifestFinal = directory.resolve(base + ".fdmanifest");
        Path signatureFinal = directory.resolve(base + ".fdsig");
        Path containerFinal = directory.resolve(base + ".fdcse");
        List<Path> finals = List.of(containerFinal, manifestFinal, signatureFinal);
        for (Path path : finals) {
            if (Files.exists(path)) {
                throw new IllegalStateException("A local artifact already exists: " + path.getFileName());
            }
        }

        String attempt = ".download-" + UUID.randomUUID() + ".part";
        Path manifestPart = directory.resolve(base + ".fdmanifest" + attempt);
        Path signaturePart = directory.resolve(base + ".fdsig" + attempt);
        Path containerPart = directory.resolve(base + ".fdcse" + attempt);
        List<Path> parts = List.of(containerPart, manifestPart, signaturePart);
        try {
            byte[] manifest = getBytes(file.serverId(), "manifest", token, MANIFEST_LENGTH);
            byte[] signature = getBytes(file.serverId(), "signature", token, SIGNATURE_LENGTH);
            Files.write(manifestPart, manifest);
            Files.write(signaturePart, signature);

            MessageDigest digest = MessageDigest.getInstance("SHA3-512");
            HttpResponse<InputStream> response = send(file.serverId(), "container", token,
                    HttpResponse.BodyHandlers.ofInputStream());
            requireSuccess(response.statusCode());
            long received = 0;
            try (InputStream input = response.body(); var output = Files.newOutputStream(containerPart)) {
                byte[] buffer = new byte[1024 * 1024];
                for (int count; (count = input.read(buffer)) != -1; ) {
                    output.write(buffer, 0, count);
                    digest.update(buffer, 0, count);
                    received = Math.addExact(received, count);
                }
            }

            ByteBuffer signed = ByteBuffer.wrap(manifest).order(ByteOrder.LITTLE_ENDIAN);
            long signedRevision = signed.getLong(32);
            long signedSize = signed.getLong(40);
            byte[] signedHash = Arrays.copyOfRange(manifest, 48, 112);
            if (signedRevision != file.revision() || signedSize != received
                    || !MessageDigest.isEqual(signedHash, digest.digest())) {
                throw new IllegalStateException("Downloaded container does not match its signed manifest.");
            }

            byte[] header = readHeader(containerPart);
            JsonNode metadata = JSON.readTree(NativeCryptoBridge.decryptPrivateMetadataV3(
                    manifest, signature, header));
            if (!file.clientFileId().equals(UUID.fromString(metadata.path("clientFileId").asText()))
                    || file.revision() != metadata.path("revision").asLong(-1)) {
                throw new IllegalStateException("Downloaded metadata does not match the selected file.");
            }

            moveNew(containerPart, containerFinal);
            try {
                moveNew(manifestPart, manifestFinal);
                moveNew(signaturePart, signatureFinal);
            } catch (Exception error) {
                Files.deleteIfExists(containerFinal);
                Files.deleteIfExists(manifestFinal);
                throw error;
            }
        } catch (Exception error) {
            throw new IllegalStateException("Lockbox download failed: " + error.getMessage(), error);
        } finally {
            for (Path part : parts) try { Files.deleteIfExists(part); } catch (Exception ignored) {}
        }
    }

    private byte[] getBytes(long id, String artifact, String token, int expected) throws Exception {
        HttpResponse<byte[]> response = send(id, artifact, token, HttpResponse.BodyHandlers.ofByteArray());
        requireSuccess(response.statusCode());
        if (response.body().length != expected) {
            throw new IllegalStateException("Invalid downloaded " + artifact + " length.");
        }
        return response.body();
    }

    private <T> HttpResponse<T> send(long id, String artifact, String token,
                                     HttpResponse.BodyHandler<T> handler) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(
                        URI.create(BASE + Long.toString(id) + "/" + artifact))
                .timeout(Duration.ofHours(12))
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/octet-stream")
                .GET().build();
        return http.send(request, handler);
    }

    private void requireSuccess(int status) {
        if (status == 401 || status == 403) throw new IllegalStateException("Session is unauthorized.");
        if (status != 200) throw new IllegalStateException("Download returned HTTP " + status + ".");
    }

    private byte[] readHeader(Path container) throws Exception {
        try (InputStream input = Files.newInputStream(container)) {
            byte[] preamble = input.readNBytes(32);
            if (preamble.length != 32) throw new IllegalStateException("Container header is truncated.");
            long length = Integer.toUnsignedLong(ByteBuffer.wrap(preamble, 12, 4)
                    .order(ByteOrder.LITTLE_ENDIAN).getInt());
            if (length < 32 || length > 1024 * 1024) throw new IllegalStateException("Invalid header length.");
            byte[] header = new byte[(int) length];
            System.arraycopy(preamble, 0, header, 0, 32);
            byte[] rest = input.readNBytes((int) length - 32);
            if (rest.length != length - 32) throw new IllegalStateException("Container header is truncated.");
            System.arraycopy(rest, 0, header, 32, rest.length);
            return header;
        }
    }

    private void moveNew(Path source, Path target) throws Exception {
        try {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException error) {
            Files.move(source, target);
        }
    }
}
