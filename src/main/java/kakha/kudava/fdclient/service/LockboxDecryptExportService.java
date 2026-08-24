package kakha.kudava.fdclient.service;

import kakha.kudava.fdclient.crypto.NativeCryptoBridge;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;

public final class LockboxDecryptExportService {
    private static final int MANIFEST_LENGTH = 264;
    private static final int SIGNATURE_LENGTH = 4_675;

    public CompletableFuture<Void> decryptAndExport(
            LockboxMetadataService.PrivateFile file,
            Path destination
    ) {
        return CompletableFuture.runAsync(() -> decryptBlocking(file, destination));
    }

    private void decryptBlocking(
            LockboxMetadataService.PrivateFile file,
            Path destination
    ) {
        if (file == null || file.localContainerPath() == null) {
            throw new IllegalArgumentException("A complete local Lockbox file is required.");
        }
        if (destination == null) {
            throw new IllegalArgumentException("An export destination is required.");
        }
        Path container = file.localContainerPath().toAbsolutePath().normalize();
        Path output = destination.toAbsolutePath().normalize();
        if (!Files.isRegularFile(container)) {
            throw new IllegalStateException("The local encrypted container is missing.");
        }
        if (Files.exists(output)) {
            throw new IllegalStateException("The export destination already exists.");
        }
        Path directory = container.getParent();
        String base = file.clientFileId().toString();
        try {
            if (file.accessKind() == LockboxMetadataService.AccessKind.SHARED_WITH_ME) {
                var artifacts = file.shareArtifacts();
                if (file.shareId() == null || artifacts == null) {
                    throw new IllegalStateException("The local received-share information is missing.");
                }
                boolean succeeded = NativeCryptoBridge.decryptReceivedShareFileV1(
                        container.toString(), output.toString(),
                        artifacts.recipientEnvelope(), artifacts.ownerShareSignature(),
                        artifacts.ownerSigningKeyId(), artifacts.ownerSigningPublicKey(),
                        artifacts.manifest(), artifacts.fileSignature(), artifacts.encryptedHeader(),
                        LockboxReceivedShareService.uuidBytes(file.shareId()),
                        LockboxReceivedShareService.uuidBytes(artifacts.recipientPublicUuid()),
                        LockboxReceivedShareService.uuidBytes(file.clientFileId()), file.revision());
                if (!succeeded) throw new IllegalStateException("Native shared-file decryption failed.");
            } else {
                byte[] manifest = readExact(directory.resolve(base + ".fdmanifest"), MANIFEST_LENGTH);
                byte[] signature = readExact(directory.resolve(base + ".fdsig"), SIGNATURE_LENGTH);
                boolean succeeded = NativeCryptoBridge.decryptOwnedFileV3(
                        container.toString(), manifest, signature, output.toString());
                if (!succeeded) throw new IllegalStateException("Native owned-file decryption failed.");
            }
        } catch (RuntimeException error) {
            throw error;
        } catch (Exception error) {
            throw new IllegalStateException("Could not decrypt and export the Lockbox file.", error);
        }
    }

    private byte[] readExact(Path path, int expectedLength) throws Exception {
        if (!Files.isRegularFile(path) || Files.size(path) != expectedLength) {
            throw new IllegalStateException("The local Lockbox artifact set is incomplete.");
        }
        return Files.readAllBytes(path);
    }
}
