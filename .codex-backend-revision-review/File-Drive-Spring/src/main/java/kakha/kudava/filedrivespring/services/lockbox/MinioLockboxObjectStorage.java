package kakha.kudava.filedrivespring.services.lockbox;

import io.minio.*;
import kakha.kudava.filedrivespring.services.objects.ObjectStorageService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.Objects;

@Component
public class MinioLockboxObjectStorage
        implements LockboxObjectStorage {

    private final MinioClient minioClient;
    private final String lockboxBucket;

    public MinioLockboxObjectStorage(
            MinioClient minioClient,
            @Value("${s3.lockbox-bucket}")
            String lockboxBucket
    ) {
        this.minioClient = Objects.requireNonNull(
                minioClient,
                "minioClient"
        );

        if (lockboxBucket == null || lockboxBucket.isBlank()) {
            throw new IllegalArgumentException(
                    "Lockbox bucket must be configured."
            );
        }

        this.lockboxBucket = lockboxBucket;
    }

    @Override
    public void upload(
            String objectKey,
            Path source,
            ArtifactType artifactType
    ) throws Exception {
        requireObjectKey(objectKey);
        Objects.requireNonNull(source, "source");

        if (!Files.isRegularFile(
                source,
                LinkOption.NOFOLLOW_LINKS
        )) {
            throw new IllegalArgumentException(
                    "Lockbox upload source must be a regular file."
            );
        }

        long size = Files.size(source);

        try (InputStream input = Files.newInputStream(source)) {
            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(lockboxBucket)
                            .object(objectKey)
                            .stream(input, size, -1)
                            .contentType(Objects.requireNonNull(artifactType).contentType())
                            .build()
            );
        }
    }

    @Override
    public InputStream download(
            String objectKey
    ) throws Exception {

        requireObjectKey(objectKey);

        return minioClient.getObject(
                GetObjectArgs.builder()
                        .bucket(lockboxBucket)
                        .object(objectKey)
                        .build()
        );
    }

    @Override
    public long size(
            String objectKey
    ) throws Exception {

        requireObjectKey(objectKey);

        return minioClient.statObject(
                StatObjectArgs.builder()
                        .bucket(lockboxBucket)
                        .object(objectKey)
                        .build()
        ).size();
    }

    @Override
    public void delete(
            String objectKey
    ) throws Exception {

        requireObjectKey(objectKey);

        minioClient.removeObject(
                RemoveObjectArgs.builder()
                        .bucket(lockboxBucket)
                        .object(objectKey)
                        .build()
        );
    }

    private void requireObjectKey(String objectKey) {
        if (objectKey == null || objectKey.isBlank()) {
            throw new IllegalArgumentException(
                    "Lockbox object key is required."
            );
        }
    }
}
