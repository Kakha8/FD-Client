package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Flow;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.DoubleConsumer;

public final class LockboxUploadService {

    private static final URI UPLOAD_URI =
            BackendConfig.uri("/api/lockbox/files");

    private static final Duration CONNECT_TIMEOUT =
            Duration.ofSeconds(15);

    private static final Duration UPLOAD_TIMEOUT =
            Duration.ofHours(12);

    /*
     * Prevent thousands of JavaFX runLater calls during a large upload.
     */
    private static final long PROGRESS_REPORT_INTERVAL_NANOS =
            Duration.ofMillis(50).toNanos();

    private final ObjectMapper objectMapper =
            new ObjectMapper();

    private final HttpClient httpClient =
            HttpClient.newBuilder()
                    .connectTimeout(CONNECT_TIMEOUT)
                    .build();

    /**
     * Uploads the complete signed CSEMLK03 artifact set.
     * @param parentFolderId null uploads to the Lockbox root
     * @param accessToken current bearer access token
     * @param progressListener receives values from 0.0 through 1.0
     */
    public CompletableFuture<UploadResult> upload(
            CseEncryptionService.V3Artifacts artifacts,
            Long parentFolderId,
            String accessToken,
            DoubleConsumer progressListener
    ) {
        Objects.requireNonNull(
                artifacts,
                "artifacts"
        );
        Objects.requireNonNull(
                progressListener,
                "progressListener"
        );

        if (!validArtifactSet(artifacts)) {
            return CompletableFuture.failedFuture(
                    new UploadException(
                            "The complete encrypted artifact set does not exist or is inconsistent."
                    )
            );
        }

        if (accessToken == null || accessToken.isBlank()) {
            return CompletableFuture.failedFuture(
                    new UploadException(
                            "No authenticated session is available."
                    )
            );
        }

        final HttpRequest.BodyPublisher multipartBody;
        final String boundary =
                "----FDClientBoundary" + UUID.randomUUID();

        try {
            multipartBody = createMultipartBody(
                    artifacts,
                    boundary
            );
        } catch (Exception exception) {
            return CompletableFuture.failedFuture(
                    new UploadException(
                            "Could not prepare the encrypted file upload.",
                            exception
                    )
            );
        }

        HttpRequest.BodyPublisher progressBody =
                new ProgressBodyPublisher(
                        multipartBody,
                        progressListener
                );

        HttpRequest request = HttpRequest.newBuilder()
                .uri(uploadUri(parentFolderId))
                .timeout(UPLOAD_TIMEOUT)
                .header(
                        "Authorization",
                        "Bearer " + accessToken
                )
                .header(
                        "Content-Type",
                        "multipart/form-data; boundary=" + boundary
                )
                .header("Accept", "application/json")
                .POST(progressBody)
                .build();

        progressListener.accept(0.0);

        return httpClient.sendAsync(
                        request,
                        HttpResponse.BodyHandlers.ofString(
                                StandardCharsets.UTF_8
                        )
                )
                .thenApply(response -> handleResponse(response, artifacts));
    }

    public CompletableFuture<UploadResult> uploadRevision(
            long fileId,
            long expectedRevision,
            CseEncryptionService.V3Artifacts artifacts,
            String accessToken,
            DoubleConsumer progressListener
    ) {
        if (fileId < 1 || expectedRevision < 1
                || artifacts == null || artifacts.revision() != expectedRevision + 1) {
            return CompletableFuture.failedFuture(
                    new UploadException("The Lockbox revision request is invalid."));
        }
        Objects.requireNonNull(progressListener, "progressListener");
        if (!validArtifactSet(artifacts)) {
            return CompletableFuture.failedFuture(
                    new UploadException("The complete revision artifact set is unavailable."));
        }
        if (accessToken == null || accessToken.isBlank()) {
            return CompletableFuture.failedFuture(
                    new UploadException("No authenticated session is available."));
        }

        String boundary = "----FDClientBoundary" + UUID.randomUUID();
        final HttpRequest.BodyPublisher multipartBody;
        try {
            multipartBody = createMultipartBody(artifacts, boundary);
        } catch (Exception error) {
            return CompletableFuture.failedFuture(
                    new UploadException("Could not prepare the revision upload.", error));
        }
        HttpRequest request = HttpRequest.newBuilder()
                .uri(BackendConfig.uri("/api/lockbox/files/" + fileId
                        + "/revisions?expectedRevision=" + expectedRevision))
                .timeout(UPLOAD_TIMEOUT)
                .header("Authorization", "Bearer " + accessToken)
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .header("Accept", "application/json")
                .PUT(new ProgressBodyPublisher(multipartBody, progressListener))
                .build();
        progressListener.accept(0.0);
        return httpClient.sendAsync(request,
                        HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                .thenApply(response -> {
                    if (response.statusCode() == 409) {
                        throw new UploadException(
                                "This file changed on another device. Refresh and try again.");
                    }
                    return handleResponse(response, artifacts);
                });
    }

    private HttpRequest.BodyPublisher createMultipartBody(
            CseEncryptionService.V3Artifacts artifacts,
            String boundary
    ) throws Exception {
        List<HttpRequest.BodyPublisher> publishers =
                new ArrayList<>();
        addFilePart(publishers, boundary, "container", artifacts.containerPath(),
                "application/x-filedrive-csemlk03");
        addFilePart(publishers, boundary, "manifest", artifacts.manifestPath(),
                "application/x-filedrive-lockbox-manifest");
        addFilePart(publishers, boundary, "signature", artifacts.signaturePath(),
                "application/x-filedrive-lockbox-signature");

        String closingBoundary =
                "--" + boundary + "--\r\n";

        publishers.add(
                HttpRequest.BodyPublishers.ofByteArray(
                        closingBoundary.getBytes(
                                StandardCharsets.UTF_8
                        )
                )
        );

        return HttpRequest.BodyPublishers.concat(
                publishers.toArray(
                        HttpRequest.BodyPublisher[]::new
                )
        );
    }

    private void addFilePart(List<HttpRequest.BodyPublisher> publishers,
                             String boundary, String field, Path file,
                             String contentType) throws Exception {
        String header = "--" + boundary + "\r\n"
                + "Content-Disposition: form-data; name=\"" + field
                + "\"; filename=\"" + safeMultipartFileName(file.getFileName().toString()) + "\"\r\n"
                + "Content-Type: " + contentType + "\r\n\r\n";
        publishers.add(HttpRequest.BodyPublishers.ofByteArray(header.getBytes(StandardCharsets.UTF_8)));
        publishers.add(HttpRequest.BodyPublishers.ofFile(file));
        publishers.add(HttpRequest.BodyPublishers.ofByteArray("\r\n".getBytes(StandardCharsets.UTF_8)));
    }

    private URI uploadUri(Long parentFolderId) {
        if (parentFolderId == null) return UPLOAD_URI;
        if (parentFolderId < 1) throw new UploadException("Parent folder ID must be positive.");
        return URI.create(UPLOAD_URI + "?parentFolderId=" + parentFolderId);
    }

    private boolean validArtifactSet(CseEncryptionService.V3Artifacts artifacts) {
        String base = artifacts.clientFileId().toString();
        return artifactMatches(artifacts.containerPath(), base + ".fdcse")
                && artifactMatches(artifacts.manifestPath(), base + ".fdmanifest")
                && artifactMatches(artifacts.signaturePath(), base + ".fdsig");
    }

    private boolean artifactMatches(Path path, String expectedName) {
        return path != null && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                && path.getFileName().toString().equals(expectedName);
    }

    private UploadResult handleResponse(
            HttpResponse<String> response,
            CseEncryptionService.V3Artifacts expected
    ) {
        int status = response.statusCode();

        if (status == 200 || status == 201) {
            try {
                JsonNode json =
                        objectMapper.readTree(response.body());

                UploadResult result = new UploadResult(
                        json.path("id").asLong(),
                        UUID.fromString(json.path("clientFileId").asText()),
                        json.path("revision").asLong(),
                        nullableLong(json.get("parentId")),
                        json.path("containerSize").asLong(),
                        json.path("containerHash").asText(),
                        json.path("formatVersion").asInt(),
                        json.path("suiteId").asInt(),
                        parseInstant(json.path("createdAt").asText())
                );
                if (result.id() < 1
                        || !result.clientFileId().equals(expected.clientFileId())
                        || result.revision() != expected.revision()
                        || result.containerSize() != expected.containerSize()
                        || !result.containerHash().equalsIgnoreCase(expected.containerHash())
                        || result.formatVersion() != 3
                        || result.suiteId() != 1) {
                    throw new UploadException(
                            "The server response does not match the uploaded CSEMLK03 artifacts."
                    );
                }
                return result;
            } catch (Exception exception) {
                throw new CompletionException(
                        new UploadException(
                                "The server accepted the upload, "
                                        + "but its response could not be read.",
                                exception
                        )
                );
            }
        }

        if (status == 401 || status == 403) {
            throw new UploadException(
                    "The session is no longer authorized. "
                            + "Log in again and retry the upload."
            );
        }

        throw new UploadException(
                "Lockbox upload failed with HTTP "
                        + status
                        + responseDetails(response.body())
        );
    }

    private Long nullableLong(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }

        return node.asLong();
    }

    private Instant parseInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }

        return Instant.parse(value);
    }

    private String responseDetails(String body) {
        if (body == null || body.isBlank()) {
            return ".";
        }

        String compact = body
                .replace('\r', ' ')
                .replace('\n', ' ')
                .trim();

        if (compact.length() > 1_000) {
            compact = compact.substring(0, 1_000) + "...";
        }

        return ". Response: " + compact;
    }

    private String safeMultipartFileName(String fileName) {
        String safe = fileName
                .replace('\\', '_')
                .replace('"', '_')
                .replace('\r', '_')
                .replace('\n', '_');

        return safe.isBlank()
                ? "encrypted-file.cseml"
                : safe;
    }

    public record UploadResult(
            long id,
            UUID clientFileId,
            long revision,
            Long parentId,
            long containerSize,
            String containerHash,
            int formatVersion,
            int suiteId,
            Instant createdAt
    ) {
    }

    public static final class UploadException
            extends RuntimeException {

        public UploadException(String message) {
            super(message);
        }

        public UploadException(
                String message,
                Throwable cause
        ) {
            super(message, cause);
        }
    }

    /**
     * Wraps a normal Java HttpClient body publisher and reports how
     * many request-body bytes have been handed to the HTTP client.
     *
     * This is upload progress, not server-side processing progress.
     */
    private static final class ProgressBodyPublisher
            implements HttpRequest.BodyPublisher {

        private final HttpRequest.BodyPublisher delegate;
        private final DoubleConsumer progressListener;
        private final long contentLength;

        private ProgressBodyPublisher(
                HttpRequest.BodyPublisher delegate,
                DoubleConsumer progressListener
        ) {
            this.delegate = Objects.requireNonNull(
                    delegate,
                    "delegate"
            );
            this.progressListener = Objects.requireNonNull(
                    progressListener,
                    "progressListener"
            );
            this.contentLength = delegate.contentLength();

            if (contentLength <= 0) {
                throw new IllegalArgumentException(
                        "Upload body must have a known positive length."
                );
            }
        }

        @Override
        public long contentLength() {
            return contentLength;
        }

        @Override
        public void subscribe(
                Flow.Subscriber<? super ByteBuffer> subscriber
        ) {
            Objects.requireNonNull(subscriber, "subscriber");

            delegate.subscribe(
                    new Flow.Subscriber<>() {

                        private final AtomicLong uploaded =
                                new AtomicLong();

                        private final AtomicLong lastReportNanos =
                                new AtomicLong();

                        @Override
                        public void onSubscribe(
                                Flow.Subscription subscription
                        ) {
                            subscriber.onSubscribe(subscription);
                        }

                        @Override
                        public void onNext(ByteBuffer item) {
                            int byteCount = item.remaining();

                            subscriber.onNext(item);

                            long sent =
                                    uploaded.addAndGet(byteCount);

                            reportProgress(sent);
                        }

                        @Override
                        public void onError(Throwable throwable) {
                            subscriber.onError(throwable);
                        }

                        @Override
                        public void onComplete() {
                            // The request body has reached the HTTP client, but the
                            // backend still has to hash, validate, and store it.
                            progressListener.accept(-1.0);
                            subscriber.onComplete();
                        }

                        private void reportProgress(long sent) {
                            long now = System.nanoTime();
                            long previous =
                                    lastReportNanos.get();

                            boolean completed =
                                    sent >= contentLength;

                            boolean reportDue =
                                    now - previous
                                            >= PROGRESS_REPORT_INTERVAL_NANOS;

                            if (!completed && !reportDue) {
                                return;
                            }

                            if (!completed
                                    && !lastReportNanos
                                    .compareAndSet(previous, now)) {
                                return;
                            }

                            double progress =
                                    Math.min(
                                            0.95,
                                            (double) sent
                                                    / contentLength
                                    );

                            progressListener.accept(progress);
                        }
                    }
            );
        }
    }
}
