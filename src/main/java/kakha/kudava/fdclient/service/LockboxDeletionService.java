package kakha.kudava.fdclient.service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public final class LockboxDeletionService {

    private static final URI FILES_URI = URI.create(
            "https://localhost:8443/api/lockbox/files/"
    );

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(15))
            .build();

    public CompletableFuture<Void> deleteWeb(
            Long serverId,
            String accessToken
    ) {
        if (serverId == null || serverId < 1) {
            return CompletableFuture.failedFuture(
                    new IllegalArgumentException("A web Lockbox file is required.")
            );
        }
        if (accessToken == null || accessToken.isBlank()) {
            return CompletableFuture.failedFuture(
                    new IllegalStateException("No authenticated session is available.")
            );
        }

        HttpRequest request = HttpRequest.newBuilder(
                        URI.create(FILES_URI + serverId.toString())
                )
                .timeout(Duration.ofMinutes(2))
                .header("Authorization", "Bearer " + accessToken)
                .DELETE()
                .build();

        return http.sendAsync(
                        request,
                        HttpResponse.BodyHandlers.discarding()
                )
                .thenApply(response -> {
                    int status = response.statusCode();
                    if (status == 401 || status == 403) {
                        throw new IllegalStateException(
                                "Your session is no longer authorized."
                        );
                    }
                    if (status != 204 && status != 200) {
                        throw new IllegalStateException(
                                "Lockbox deletion failed with HTTP " + status + "."
                        );
                    }
                    return null;
                });
    }

    public CompletableFuture<Void> deleteLocal(
            LockboxMetadataService.PrivateFile file
    ) {
        return CompletableFuture.runAsync(() -> deleteLocalBlocking(file));
    }

    private void deleteLocalBlocking(
            LockboxMetadataService.PrivateFile file
    ) {
        if (file == null || file.localContainerPath() == null) {
            throw new IllegalArgumentException("A local Lockbox file is required.");
        }

        Path container = file.localContainerPath().toAbsolutePath().normalize();
        Path directory = container.getParent();
        if (directory == null) {
            throw new IllegalStateException("The local artifact directory is invalid.");
        }

        String base = file.clientFileId().toString();
        List<Path> artifacts = new java.util.ArrayList<>(List.of(
                directory.resolve(base + ".fdcse"),
                directory.resolve(base + ".fdmanifest"),
                directory.resolve(base + ".fdsig")
        ));
        if (file.accessKind() == LockboxMetadataService.AccessKind.SHARED_WITH_ME) {
            artifacts.add(directory.resolve(base + ".fdshare"));
        }

        try {
            for (Path artifact : artifacts) {
                Files.deleteIfExists(artifact);
            }
        } catch (Exception error) {
            throw new IllegalStateException(
                    "The local Lockbox artifacts could not be deleted.",
                    error
            );
        }
    }
}
