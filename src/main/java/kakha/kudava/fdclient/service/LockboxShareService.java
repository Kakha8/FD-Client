package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import kakha.kudava.fdclient.crypto.NativeCryptoBridge;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

public final class LockboxShareService {
    static final byte[] GRANT_DOMAIN =
            "FD-CSE-V3-SHARE-GRANT-V1\0".getBytes(StandardCharsets.US_ASCII);
    private static final URI SHARES_URI = BackendConfig.uri("/api/lockbox/shares");
    private static final ObjectMapper JSON = new ObjectMapper();

    private final AuthService auth;
    private final LockboxRecipientKeyService recipients;
    private final HttpClient http;
    private final GrantFactory grants;

    public LockboxShareService(AuthService auth) {
        this(auth, new LockboxRecipientKeyService(auth),
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build(),
                LockboxShareService::nativeGrant);
    }

    LockboxShareService(AuthService auth, LockboxRecipientKeyService recipients,
                        HttpClient http, GrantFactory grants) {
        this.auth = Objects.requireNonNull(auth, "auth");
        this.recipients = Objects.requireNonNull(recipients, "recipients");
        this.http = Objects.requireNonNull(http, "http");
        this.grants = Objects.requireNonNull(grants, "grants");
    }

    public CompletableFuture<ShareResult> share(
            LockboxMetadataService.PrivateFile file,
            String recipientUsername,
            long expiresAtUnixSeconds
    ) {
        if (file == null || file.serverId() == null || file.localContainerPath() == null) {
            return CompletableFuture.failedFuture(new ShareException(
                    "Sharing requires both the local artifacts and web copy."));
        }
        if (!auth.isAuthenticated()) {
            return CompletableFuture.failedFuture(new ShareException("Log in before sharing a file."));
        }
        return recipients.lookup(recipientUsername).thenCompose(recipient ->
                CompletableFuture.supplyAsync(() -> grants.create(
                        artifacts(file), auth.getPublicUuid(), recipient,
                        expiresAtUnixSeconds)).thenCompose(grant -> postWithOneRefresh(
                                file.serverId(), grant, false)));
    }

    private CompletableFuture<ShareResult> postWithOneRefresh(
            long fileId, LockboxShareGrant grant, boolean retried
    ) {
        final HttpRequest request;
        try {
            request = request(fileId, grant, auth.getAccessToken());
        } catch (Exception error) {
            return CompletableFuture.failedFuture(error);
        }
        return http.sendAsync(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8))
                .thenCompose(response -> {
                    if ((response.statusCode() == 401 || response.statusCode() == 403) && !retried) {
                        return auth.refresh().thenCompose(ignored ->
                                postWithOneRefresh(fileId, grant, true));
                    }
                    try {
                        return CompletableFuture.completedFuture(handle(response));
                    } catch (RuntimeException error) {
                        return CompletableFuture.failedFuture(error);
                    }
                });
    }

    private HttpRequest request(long fileId, LockboxShareGrant grant, String token) throws Exception {
        ObjectNode body = JSON.createObjectNode();
        Base64.Encoder base64 = Base64.getEncoder();
        body.put("fileId", fileId);
        body.put("envelope", base64.encodeToString(grant.envelope()));
        body.put("ownerSigningKeyId", base64.encodeToString(grant.ownerSigningKeyId()));
        body.put("ownerSignature", base64.encodeToString(grant.ownerSignature()));
        return HttpRequest.newBuilder(SHARES_URI)
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)))
                .build();
    }

    private ShareResult handle(HttpResponse<String> response) {
        int status = response.statusCode();
        if (status == 201) {
            try {
                JsonNode body = JSON.readTree(response.body());
                UUID shareId = UUID.fromString(body.path("shareId").asText());
                long fileId = body.path("fileId").asLong(-1);
                String recipient = body.path("recipientUsername").asText("");
                String state = body.path("status").asText("");
                if (fileId < 1 || recipient.isBlank() || !"ACTIVE".equals(state)) {
                    throw new IllegalArgumentException();
                }
                return new ShareResult(shareId, fileId, recipient, state);
            } catch (Exception error) {
                throw new ShareException("The server returned an invalid create-share response.", error);
            }
        }
        if (status == 409) throw new ShareException("This file is already shared with that recipient.");
        if (status == 404) throw new ShareException("The file or recipient is no longer available.");
        if (status == 400) throw new ShareException("The server rejected the Lockbox share grant.");
        if (status == 401 || status == 403) throw new ShareException("Your session is no longer authorized.");
        throw new ShareException("Lockbox sharing failed with HTTP " + status + ".");
    }

    private static ArtifactPaths artifacts(LockboxMetadataService.PrivateFile file) {
        Path container = file.localContainerPath().toAbsolutePath().normalize();
        Path directory = container.getParent();
        String id = file.clientFileId().toString();
        Path manifest = directory.resolve(id + ".fdmanifest");
        Path signature = directory.resolve(id + ".fdsig");
        if (!Files.isRegularFile(container) || !Files.isRegularFile(manifest)
                || !Files.isRegularFile(signature)) {
            throw new ShareException("The local Lockbox artifact set is incomplete.");
        }
        return new ArtifactPaths(container, manifest, signature);
    }

    private static LockboxShareGrant nativeGrant(
            ArtifactPaths paths, UUID ownerId, LockboxRecipientKeys recipient, long expiry
    ) {
        byte[] envelope = NativeCryptoBridge.createRecipientShareEnvelopeV1(
                paths.container().toString(), paths.manifest().toString(), paths.signature().toString(),
                uuidBytes(ownerId), uuidBytes(recipient.recipientPublicUuid()),
                recipient.primaryEncryptionKey().publicKey(), expiry);
        if (envelope == null || envelope.length != LockboxShareGrant.ENVELOPE_LENGTH) {
            throw new ShareException("Native share-envelope generation failed.");
        }
        byte[] message = grantMessage(envelope);
        byte[] keyId = NativeCryptoBridge.getStoredMlDsa87KeyId();
        byte[] signature = NativeCryptoBridge.signWithStoredMlDsa87(message);
        return new LockboxShareGrant(envelope, keyId, signature);
    }

    static byte[] uuidBytes(UUID value) {
        return ByteBuffer.allocate(16).putLong(value.getMostSignificantBits())
                .putLong(value.getLeastSignificantBits()).array();
    }

    static byte[] grantMessage(byte[] envelope) {
        Objects.requireNonNull(envelope, "envelope");
        if (envelope.length != LockboxShareGrant.ENVELOPE_LENGTH) {
            throw new IllegalArgumentException("Invalid share envelope length.");
        }
        byte[] message = new byte[GRANT_DOMAIN.length + envelope.length];
        System.arraycopy(GRANT_DOMAIN, 0, message, 0, GRANT_DOMAIN.length);
        System.arraycopy(envelope, 0, message, GRANT_DOMAIN.length, envelope.length);
        return message;
    }

    @FunctionalInterface interface GrantFactory {
        LockboxShareGrant create(ArtifactPaths paths, UUID ownerId,
                                 LockboxRecipientKeys recipient, long expiry);
    }
    record ArtifactPaths(Path container, Path manifest, Path signature) {}
    public record ShareResult(UUID shareId, long fileId, String recipientUsername, String status) {}
    public static final class ShareException extends RuntimeException {
        public ShareException(String message) { super(message); }
        public ShareException(String message, Throwable cause) { super(message, cause); }
    }
}
