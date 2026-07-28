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
            URI.create(
                    "https://localhost:8443/api/lockbox/files"
            );

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
     * Uploads an already encrypted .cseml/.fdcse file.
     *
     * @param encryptedFile encrypted container produced by Rust
     * @param parentFolderId null uploads to the Lockbox root
     * @param accessToken current bearer access token
     * @param progressListener receives values from 0.0 through 1.0
     */
    public CompletableFuture<UploadResult> upload(
            Path encryptedFile,
            Long parentFolderId,
            String accessToken,
            DoubleConsumer progressListener
    ) {
        Objects.requireNonNull(
                encryptedFile,
                "encryptedFile"
        );
        Objects.requireNonNull(
                progressListener,
                "progressListener"
        );

        if (!Files.isRegularFile(
                encryptedFile,
                LinkOption.NOFOLLOW_LINKS
        )) {
            return CompletableFuture.failedFuture(
                    new UploadException(
                            "The encrypted output file does not exist."
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
                    encryptedFile,
                    parentFolderId,
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
                .uri(UPLOAD_URI)
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
                .thenApply(this::handleResponse);
    }

    private HttpRequest.BodyPublisher createMultipartBody(
            Path encryptedFile,
            Long parentFolderId,
            String boundary
    ) throws Exception {
        String safeFileName =
                safeMultipartFileName(
                        encryptedFile.getFileName().toString()
                );

        List<HttpRequest.BodyPublisher> publishers =
                new ArrayList<>();

        String fileHeader =
                "--" + boundary + "\r\n"
                        + "Content-Disposition: form-data; "
                        + "name=\"file\"; "
                        + "filename=\"" + safeFileName + "\"\r\n"
                        + "Content-Type: application/octet-stream\r\n"
                        + "\r\n";

        publishers.add(
                HttpRequest.BodyPublishers.ofByteArray(
                        fileHeader.getBytes(StandardCharsets.UTF_8)
                )
        );

        publishers.add(
                HttpRequest.BodyPublishers.ofFile(
                        encryptedFile
                )
        );

        publishers.add(
                HttpRequest.BodyPublishers.ofByteArray(
                        "\r\n".getBytes(StandardCharsets.UTF_8)
                )
        );

        if (parentFolderId != null) {
            String parentPart =
                    "--" + boundary + "\r\n"
                            + "Content-Disposition: form-data; "
                            + "name=\"parentFolderId\"\r\n"
                            + "Content-Type: text/plain; "
                            + "charset=UTF-8\r\n"
                            + "\r\n"
                            + parentFolderId
                            + "\r\n";

            publishers.add(
                    HttpRequest.BodyPublishers.ofByteArray(
                            parentPart.getBytes(
                                    StandardCharsets.UTF_8
                            )
                    )
            );
        }

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

    private UploadResult handleResponse(
            HttpResponse<String> response
    ) {
        int status = response.statusCode();

        if (status == 200 || status == 201) {
            try {
                JsonNode json =
                        objectMapper.readTree(response.body());

                return new UploadResult(
                        json.path("id").asLong(),
                        json.path("fileName").asText(),
                        nullableLong(json.get("parentId")),
                        json.path("ciphertextSize").asLong(),
                        json.path("ciphertextChecksum").asText(),
                        json.path("formatVersion").asInt(),
                        json.path("algorithmSuite").asText(),
                        json.path("chunkSize").asInt(),
                        parseInstant(json.path("createdAt").asText())
                );
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
            String fileName,
            Long parentId,
            long ciphertextSize,
            String ciphertextChecksum,
            int formatVersion,
            String algorithmSuite,
            int chunkSize,
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
                            progressListener.accept(1.0);
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
                                            1.0,
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