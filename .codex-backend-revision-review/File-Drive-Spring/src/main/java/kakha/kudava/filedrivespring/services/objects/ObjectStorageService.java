package kakha.kudava.filedrivespring.services.objects;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.minio.*;
import io.minio.messages.DeleteError;
import io.minio.messages.DeleteObject;
import io.minio.messages.Item;
import jakarta.transaction.Transactional;
import kakha.kudava.filedrivespring.enums.EntityType;
import kakha.kudava.filedrivespring.exceptions.MalwareDetectedException;
import kakha.kudava.filedrivespring.exceptions.UploadCanceledException;
import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.model.QuarantinedFiles;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import kakha.kudava.filedrivespring.repository.FolderRepository;
import kakha.kudava.filedrivespring.repository.QuarantinedFilesRepository;
import kakha.kudava.filedrivespring.repository.UserRepository;
import kakha.kudava.filedrivespring.services.*;
import kakha.kudava.filedrivespring.services.notifications.NotificationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

import static org.apache.sshd.common.util.buffer.BufferUtils.toHex;

@Slf4j
@Service
public class ObjectStorageService {

    private final MinioClient minioClient;
    private final String bucket;
    private final FileMetaDataRepository fileMetaDataRepository;

    private final FolderRepository folderRepository;
    private final LogsService logsService;
    private final ObjectMapper objectMapper;
    private final ClamAvScannerService clamAvScannerService;
    private final QuarantinedFilesRepository quarantinedFilesRepository;
    private final String quarantineBucket;
    private final UserRepository userRepository;
    private final QuarantineService quarantineService;
    private final RootFolderService rootFolderService;
    private final UploadCancellationService uploadCancellationService;
    private final String trashBucket;
    private final ResourceAccessService access;
    private final NotificationService notificationService;


    public ObjectStorageService(MinioClient minioClient, @Value("${s3.bucket}") String bucket, FileMetaDataRepository fileMetaDataRepository,
                                FolderRepository folderRepository,
                                LogsService logsService, ObjectMapper objectMapper, ClamAvScannerService clamAvScannerService,
                                QuarantinedFilesRepository quarantinedFilesRepository, @Value("${s3.quarantine-bucket}") String quarantineBucket,
                                UserRepository userRepository, QuarantineService quarantineService,
                                RootFolderService rootFolderService, UploadCancellationService uploadCancellationService,
                                @Value("${s3.trash-bucket}") String trashBucket, ResourceAccessService access, NotificationService notificationService) {
        this.minioClient = minioClient;
        this.bucket = bucket;
        this.fileMetaDataRepository = fileMetaDataRepository;
        this.folderRepository = folderRepository;
        this.logsService = logsService;
        this.objectMapper = objectMapper;
        this.clamAvScannerService = clamAvScannerService;
        this.quarantinedFilesRepository = quarantinedFilesRepository;
        this.quarantineBucket = quarantineBucket;
        this.userRepository = userRepository;
        this.quarantineService = quarantineService;
        this.rootFolderService = rootFolderService;
        this.uploadCancellationService = uploadCancellationService;
        this.trashBucket = trashBucket;
        this.access = access;
        this.notificationService = notificationService;
    }

    public FileMetaData upload(MultipartFile file, Long parentId, String uploadId) throws Exception {

        throwIfUploadCanceled(uploadId);

        MessageDigest md = MessageDigest.getInstance("SHA-256");

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        User user = userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("Authenticated user not found: " + auth.getName()));

        throwIfUploadCanceled(uploadId);

        Folders folder;

        if (parentId == null) {
            folder = rootFolderService.ensureRootFolder(user);
        } else {
            folder = access.requireFolderEdit(parentId);
        }

        throwIfUploadCanceled(uploadId);

        String safeName = file.getOriginalFilename() == null ? "file" : file.getOriginalFilename();

        String prefix = folder.getPrefix();
        if (!prefix.endsWith("/")) {
            prefix += "/";
        }

        String objectKey = prefix + UUID.randomUUID() + "-" + safeName;

        Path tempFile = Files.createTempFile("upload-", ".scan");

        boolean uploadedToStorage = false;

        try {
            file.transferTo(tempFile);

            throwIfUploadCanceled(uploadId);

            ClamAvScannerService.ScanResult scanResult = clamAvScannerService.scan(tempFile);

            throwIfUploadCanceled(uploadId);

            if (!scanResult.clean()) {
                String quarantineKey = "quarantine/" + UUID.randomUUID() + "-" + safeName;

                try (InputStream quarantineIn = Files.newInputStream(tempFile)) {
                    minioClient.putObject(
                            PutObjectArgs.builder()
                                    .bucket(quarantineBucket)
                                    .object(quarantineKey)
                                    .stream(quarantineIn, Files.size(tempFile), -1)
                                    .contentType(file.getContentType())
                                    .build()
                    );
                }

                QuarantinedFiles quarantinedFile = new QuarantinedFiles();
                quarantinedFile.setOriginalFilename(safeName);
                quarantinedFile.setObjectKey(quarantineKey);
                quarantinedFile.setContentType(
                        file.getContentType() == null ? "application/octet-stream" : file.getContentType()
                );
                quarantinedFile.setSize(Files.size(tempFile));
                quarantinedFile.setChecksum(sha256(tempFile));
                quarantinedFile.setClamAvResponse(scanResult.response());
                quarantinedFile.setParentFolderId(folder.getId());
                quarantinedFile.setUser(user);

                quarantineService.save(quarantinedFile);

                Map<String, Object> details = new LinkedHashMap<>();
                details.put("originalFilename", safeName);
                details.put("quarantineBucket", quarantineBucket);
                details.put("quarantineKey", quarantineKey);
                details.put("clamAvResponse", scanResult.response());
                details.put("size", Files.size(tempFile));
                details.put("checksum", quarantinedFile.getChecksum());
                details.put("user_id", quarantinedFile.getUser().getId());

                String detailsJson = objectMapper.writeValueAsString(details);

                logsService.malwareUploadLog(safeName, folder.getId(), "FILE", detailsJson);

                log.warn(
                        "Blocked infected upload and moved to quarantine: fileName={}, quarantineBucket={}, quarantineKey={}, response={}",
                        safeName,
                        quarantineBucket,
                        quarantineKey,
                        scanResult.response()
                );
                notificationService.notifyMalwareDetected(
                        user,
                        safeName
                );

                throw new MalwareDetectedException("Upload rejected: malware detected");
            }

            throwIfUploadCanceled(uploadId);

            try (InputStream in = Files.newInputStream(tempFile);
                 DigestInputStream dis = new DigestInputStream(in, md)) {

                PutObjectArgs.Builder putBuilder = PutObjectArgs.builder()
                        .bucket(bucket)
                        .object(objectKey)
                        .stream(dis, Files.size(tempFile), -1)
                        .contentType(file.getContentType());

                minioClient.putObject(putBuilder.build());
                uploadedToStorage = true;

                throwIfUploadCanceled(uploadId);

                byte[] hash = md.digest();
                String checksum = toHex(hash);
                Long fileSize = Files.size(tempFile);

                FileMetaData entity = new FileMetaData();
                entity.setDeleted(false);
                entity.setPermanentlyDeleted(false);
                entity.setObjectKey(objectKey);
                entity.setObjectType(file.getContentType());
                entity.setFileName(safeName);
                entity.setChecksum(checksum);
                entity.setSize(fileSize);
                entity.setParent(folder);
                entity.setOwner(folder.getOwner());

                throwIfUploadCanceled(uploadId);

                FileMetaData savedFile =
                        fileMetaDataRepository.save(entity);

                log.info("File uploaded successfully {}", objectKey);
                Map<String, Object> uploadDetails = new LinkedHashMap<>();
                uploadDetails.put("name", savedFile.getFileName());
                uploadDetails.put("objectKey", savedFile.getObjectKey());
                uploadDetails.put("uploadedAt", Instant.now());
                uploadDetails.put("folderId", folder.getId());

                String uploadDetailsJson =
                        objectMapper.writeValueAsString(uploadDetails);

                logsService.uploadLog(
                        savedFile.getFileName(),
                        savedFile.getId(),
                        EntityType.FILE.name(),
                        uploadDetailsJson
                );
/*                notificationService.notifyUploadCompleted(
                        user,
                        savedFile
                );*/

                return savedFile;
            }
        } catch (UploadCanceledException ex) {
            log.warn("Upload canceled: uploadId={}, fileName={}", uploadId, safeName, ex);

            if (uploadedToStorage) {
                try {
                    minioClient.removeObject(
                            RemoveObjectArgs.builder()
                                    .bucket(bucket)
                                    .object(objectKey)
                                    .build()
                    );

                    log.info("Deleted canceled upload object from MinIO: {}", objectKey);
                } catch (Exception cleanupError) {
                    log.warn(
                            "Upload was canceled, but failed to delete object from MinIO: {}",
                            objectKey,
                            cleanupError
                    );
                }
            }

            throw ex;
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }
    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public FileMetaData getMeta(Long id) {
        return access.requireFileView(id);
    }

    public record UploadResult(String objectKey, String checksum, Long fileSize) {}



    public InputStream download(Long id) throws Exception {
        FileMetaData fileMetaData = access.requireFileView(id);

        String objectKey = fileMetaData.getObjectKey();

        log.info("Downloading object from {}", objectKey);

        logsService.downloadLog(objectKey, id, "FILE");

        return minioClient.getObject(
                GetObjectArgs.builder()
                        .bucket(bucket)
                        .object(objectKey)
                        .build()
        );
    }

    public InputStream downloadWithoutLog(Long id) throws Exception {
        FileMetaData fileMetaData = access.requireFileView(id);

        return downloadWithoutLog(fileMetaData);
    }

    /**
     * Opens an object that has already passed an access check. This overload is
     * used by asynchronous ZIP streaming, where the request security context is
     * no longer available on the worker thread.
     */
    public InputStream downloadWithoutLog(FileMetaData fileMetaData) throws Exception {

        String objectKey = fileMetaData.getObjectKey();

        log.info("Downloading object without action log from {}", objectKey);

        return minioClient.getObject(
                GetObjectArgs.builder()
                        .bucket(bucket)
                        .object(objectKey)
                        .build()
        );
    }

    public void delete(Long id) {
        FileMetaData metaData = access.requireFileOwner(id);
        User user = access.currentUser();

        if (metaData.isDeleted()) {
            throw new RuntimeException("Object is already in trash");
        }

        String originalObjectKey = metaData.getObjectKey();

        String trashObjectKey = "users/" + user.getId() + "/files/" + metaData.getId() + "/"
                + UUID.randomUUID() + "-" + metaData.getFileName();

        try {
            minioClient.copyObject(
                    CopyObjectArgs.builder()
                            .bucket(trashBucket)
                            .object(trashObjectKey)
                            .source(
                                    CopySource.builder()
                                            .bucket(bucket)
                                            .object(originalObjectKey)
                                            .build()
                            )
                            .build()
            );

            minioClient.removeObject(
                    RemoveObjectArgs.builder()
                            .bucket(bucket)
                            .object(originalObjectKey)
                            .build()
            );

            metaData.setOriginalObjectKey(originalObjectKey);
            metaData.setObjectKey(trashObjectKey);
            metaData.setDeleted(true);
            metaData.setDeletedAt(Instant.now());

            fileMetaDataRepository.save(metaData);
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("name", metaData.getFileName());
            details.put("originalObjectKey", originalObjectKey);
            details.put("trashObjectKey", trashObjectKey);
            details.put("deletedAt", Instant.now());

            String detailsJson =
                    objectMapper.writeValueAsString(details);

            logsService.moveToTrashLog(
                    metaData.getFileName(),
                    metaData.getId(),
                    EntityType.FILE.name(),
                    detailsJson
            );

        } catch (Exception e) {
            throw new RuntimeException("Failed to move object to trash", e);
        }
    }


    public void deleteByPrefix(String prefix) {
        if (prefix == null) {
            throw new IllegalArgumentException("prefix is null");
        }

        String p = prefix.trim().replace("\\", "/");

        if (p.isEmpty()) {
            throw new IllegalArgumentException("prefix is empty");
        }

        if (!p.endsWith("/")) {
            p += "/";
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        User user = userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        Folders folderToDelete = folderRepository.findByPrefixAndOwnerAndDeletedFalse(p, user)
                .orElseThrow(() -> new RuntimeException("Folder not found or not owned by user"));

        Long folderId = folderToDelete.getId();

        String trashBasePrefix = "users/" + user.getId() + "/folders/" + folderId + "/";

        Instant deletedAt = Instant.now();

        try {
            Iterable<Result<Item>> results = minioClient.listObjects(
                    ListObjectsArgs.builder()
                            .bucket(bucket)
                            .prefix(p)
                            .recursive(true)
                            .build()
            );

            for (Result<Item> result : results) {
                Item item = result.get();
                String originalObjectKey = item.objectName();

                String relativeKey = originalObjectKey.substring(p.length());
                String trashObjectKey = trashBasePrefix + relativeKey;

                minioClient.copyObject(
                        CopyObjectArgs.builder()
                                .bucket(trashBucket)
                                .object(trashObjectKey)
                                .source(
                                        CopySource.builder()
                                                .bucket(bucket)
                                                .object(originalObjectKey)
                                                .build()
                                )
                                .build()
                );

                minioClient.removeObject(
                        RemoveObjectArgs.builder()
                                .bucket(bucket)
                                .object(originalObjectKey)
                                .build()
                );

                fileMetaDataRepository.findByObjectKey(originalObjectKey)
                        .ifPresent(file -> {
                            file.setDeleted(true);
                            file.setDeletedAt(deletedAt);
                            file.setOriginalObjectKey(originalObjectKey);
                            file.setObjectKey(trashObjectKey);
                            fileMetaDataRepository.save(file);

                            String detailsJson = """
                                {
                                  "name": "%s",
                                  "originalObjectKey": "%s",
                                  "trashObjectKey": "%s",
                                  "deletedAt": "%s",
                                  "folderId": %d
                                }
                                """.formatted(
                                    file.getFileName(),
                                    originalObjectKey,
                                    trashObjectKey,
                                    deletedAt,
                                    folderId
                            );

                            logsService.moveToTrashLog(
                                    file.getFileName(),
                                    file.getId(),
                                    EntityType.FILE.name(),
                                    detailsJson
                            );
                        });

                log.info(
                        "Moved folder object to trash. originalKey={}, trashKey={}",
                        originalObjectKey,
                        trashObjectKey
                );
            }

            List<Folders> foldersInSubtree =
                    folderRepository.findByOwnerAndPrefixStartingWith(user, p);

            for (Folders folder : foldersInSubtree) {
                folder.setDeleted(true);
                folder.setDeletedAt(deletedAt);

                String folderDetailsJson = """
                    {
                      "name": "%s",
                      "prefix": "%s",
                      "trashPrefix": "%s",
                      "deletedAt": "%s"
                    }
                    """.formatted(
                        folder.getName(),
                        folder.getPrefix(),
                        "users/" + user.getId() + "/folders/" + folder.getId() + "/",
                        deletedAt
                );

                logsService.moveToTrashLog(
                        folder.getName(),
                        folder.getId(),
                        EntityType.FOLDER.name(),
                        folderDetailsJson
                );
            }

            folderRepository.saveAll(foldersInSubtree);

            log.info(
                    "Folder subtree moved to trash successfully. folderId={}, originalPrefix={}, trashPrefix={}",
                    folderId,
                    p,
                    trashBasePrefix
            );

        } catch (Exception e) {
            throw new RuntimeException("Failed to move folder to trash: " + p, e);
        }
    }

    @Transactional
    public void deleteMultipleFiles(List<Long> fileIds) {
        if (fileIds == null || fileIds.isEmpty()) {
            throw new IllegalArgumentException("No file IDs provided");
        }

        List<Long> uniqueIds = fileIds.stream()
                .filter(Objects::nonNull)
                .distinct()
                .toList();

        if (uniqueIds.isEmpty()) {
            throw new IllegalArgumentException("No valid file IDs provided");
        }

        for (Long fileId : uniqueIds) {
            delete(fileId);
        }
    }

    private void deleteBatch(List<DeleteObject> objects) throws Exception {
        Iterable<Result<DeleteError>> errors = minioClient.removeObjects(
                RemoveObjectsArgs.builder()
                        .bucket(bucket)
                        .objects(objects)
                        .build()
        );

        for (Result<DeleteError> r : errors) {
            DeleteError err = r.get();

            throw new RuntimeException(
                    "MinIO delete failed for object=" + err.objectName()
                            + " message=" + err.message()
                            + " code=" + err.code()
            );
        }
    }

    private String sha256(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        try (InputStream in = Files.newInputStream(path);
             DigestInputStream dis = new DigestInputStream(in, digest)) {

            byte[] buffer = new byte[8192];
            while (dis.read(buffer) != -1) {
                // reading updates digest
            }
        }

        return toHex(digest.digest());
    }

    private void throwIfUploadCanceled(String uploadId) {
        if (uploadCancellationService.isCanceled(uploadId)) {
            log.info("Upload cancellation detected inside upload pipeline: uploadId={}", uploadId);
            throw new UploadCanceledException("Upload canceled");
        }
    }

    public void deleteTrashObject(String objectKey) {
        try {
            minioClient.removeObject(
                    RemoveObjectArgs.builder()
                            .bucket(trashBucket)
                            .object(objectKey)
                            .build()
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to permanently delete trash object: " + objectKey, e);
        }
    }

    public void deleteTrashPrefix(String prefix) {
        try {
            Iterable<Result<Item>> results = minioClient.listObjects(
                    ListObjectsArgs.builder()
                            .bucket(trashBucket)
                            .prefix(prefix)
                            .recursive(true)
                            .build()
            );

            for (Result<Item> result : results) {
                Item item = result.get();

                minioClient.removeObject(
                        RemoveObjectArgs.builder()
                                .bucket(trashBucket)
                                .object(item.objectName())
                                .build()
                );
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to permanently delete trash prefix: " + prefix, e);
        }
    }

    public void restoreTrashObject(String trashObjectKey, String restoredObjectKey) {
        try {
            if (trashObjectKey == null || trashObjectKey.isBlank()) {
                throw new IllegalArgumentException("Trash object key is required");
            }

            if (restoredObjectKey == null || restoredObjectKey.isBlank()) {
                throw new IllegalArgumentException("Restored object key is required");
            }

            minioClient.copyObject(
                    CopyObjectArgs.builder()
                            .bucket(bucket)
                            .object(restoredObjectKey)
                            .source(
                                    CopySource.builder()
                                            .bucket(trashBucket)
                                            .object(trashObjectKey)
                                            .build()
                            )
                            .build()
            );

            minioClient.removeObject(
                    RemoveObjectArgs.builder()
                            .bucket(trashBucket)
                            .object(trashObjectKey)
                            .build()
            );
        } catch (Exception e) {
            throw new RuntimeException("Failed to restore trash object: " + trashObjectKey, e);
        }
    }

}
