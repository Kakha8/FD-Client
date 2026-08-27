package kakha.kudava.filedrivespring.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.minio.*;
import io.minio.messages.Item;
import jakarta.transaction.Transactional;
import kakha.kudava.filedrivespring.enums.EntityType;
import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import kakha.kudava.filedrivespring.repository.FolderRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.time.Instant;

@Slf4j
@Service
public class RenameService {

    private final MinioClient minioClient;
    private final String bucket;
    private final FileMetaDataRepository fileMetaDataRepository;

    private final FolderRepository folderRepository;
    private final LogsService logsService;
    private final ObjectMapper objectMapper;
    private final ResourceAccessService access;


    public RenameService(MinioClient minioClient, @Value("${s3.bucket}") String bucket, FileMetaDataRepository fileMetaDataRepository, FolderRepository folderRepository, LogsService logsService, ObjectMapper objectMapper, ResourceAccessService access) {
        this.minioClient = minioClient;
        this.bucket = bucket;
        this.fileMetaDataRepository = fileMetaDataRepository;
        this.folderRepository = folderRepository;
        this.logsService = logsService;
        this.objectMapper = objectMapper;
        this.access = access;
    }

    private void renameObject(String oldKey, String newKey) {
        try {
            minioClient.copyObject(
                    CopyObjectArgs.builder()
                            .bucket(bucket)
                            .object(newKey)
                            .source(
                                    CopySource.builder()
                                            .bucket(bucket)
                                            .object(oldKey)
                                            .build()
                            )
                            .build()
            );

            minioClient.removeObject(
                    RemoveObjectArgs.builder()
                            .bucket(bucket)
                            .object(oldKey)
                            .build()
            );

            log.info("Renamed object {} -> {}", oldKey, newKey);

        } catch (Exception e) {
            throw new RuntimeException("Failed to rename object", e);
        }
    }

    @Transactional
    public void renameFile(Long fileId, String newName) throws JsonProcessingException {

        FileMetaData meta = access.requireFileEdit(fileId);

        String oldKey = meta.getObjectKey();

        String folderPrefix = meta.getParent().getPrefix();

        String filePart = oldKey.substring(folderPrefix.length());
        String uuid = extractUuidPrefix(filePart);
        String newKey = folderPrefix + uuid + "-" + newName;
        renameObject(oldKey, newKey);

        meta.setFileName(newName);
        meta.setObjectKey(newKey);
        meta.setLastModifiedDate(Instant.now());

        String oldName = filePart.substring(37);

        fileMetaDataRepository.save(meta);

        Map<String, Object> detailsMap = new LinkedHashMap<>();

        detailsMap.put("oldName", oldName);
        detailsMap.put("newName", newName);

        String detailsJson = objectMapper.writeValueAsString(detailsMap);
        Long parentId = meta.getParent().getId();

        logsService.renameLog(oldKey, parentId, "FILE", detailsJson);
    }

    private String extractUuidPrefix(String filePart) {
        if (filePart.length() < 37) {
            throw new IllegalArgumentException("Invalid object key format: " + filePart);
        }

        String uuid = filePart.substring(0, 36);

        if (filePart.charAt(36) != '-') {
            throw new IllegalArgumentException("Invalid object key format: " + filePart);
        }

        return uuid;
    }

    @Transactional
    public void renameFolder(Long folderId, String newName) throws JsonProcessingException {
        Folders folder = access.requireFolderEdit(folderId);
        String oldPrefix = folder.getPrefix();
        Folders parent = folder.getParent();

        String parentPrefix = parent != null ? parent.getPrefix() : "";
        if (parentPrefix == null) {
            parentPrefix = "";
        }
        if (!parentPrefix.isEmpty() && !parentPrefix.endsWith("/")) {
            parentPrefix += "/";
        }

        String newPrefix = parentPrefix + newName + "/";

        if (oldPrefix.equals(newPrefix)) {
            return;
        }

        if (folderRepository.findByPrefix(newPrefix).isPresent()) {
            throw new RuntimeException("Folder already exists: " + newPrefix);
        }

        // rename all MinIO objects under oldPrefix
        renameObjectsByPrefix(oldPrefix, newPrefix);

        // update folder prefixes in DB
        List<Folders> folders = folderRepository.findByPrefixStartingWithAndDeletedFalse(oldPrefix);
        for (Folders f : folders) {
            String updatedPrefix = newPrefix + f.getPrefix().substring(oldPrefix.length());
            f.setPrefix(updatedPrefix);

            if (f.getId().equals(folderId)) {
                f.setName(newName);
            }
        }
        folderRepository.saveAll(folders);

        // update file object keys in DB
        List<FileMetaData> files = fileMetaDataRepository.findByObjectKeyStartingWithAndDeletedFalse(oldPrefix);
        for (FileMetaData file : files) {
            String updatedKey = newPrefix + file.getObjectKey().substring(oldPrefix.length());
            file.setObjectKey(updatedKey);
        }
        fileMetaDataRepository.saveAll(files);

        Map<String, Object> detailsMap = new LinkedHashMap<>();
        detailsMap.put("oldName", oldPrefix);
        detailsMap.put("newName", newName);

        String detailsJson = objectMapper.writeValueAsString(detailsMap);

        logsService.renameLog(folder.getName(), folderId, "FOLDER", detailsJson);

    }

    private void renameObjectsByPrefix(String oldPrefix, String newPrefix) {
        try {
            Iterable<Result<Item>> results = minioClient.listObjects(
                    ListObjectsArgs.builder()
                            .bucket(bucket)
                            .prefix(oldPrefix)
                            .recursive(true)
                            .build()
            );

            for (Result<Item> r : results) {
                Item item = r.get();
                String oldKey = item.objectName();
                String newKey = newPrefix + oldKey.substring(oldPrefix.length());

                minioClient.copyObject(
                        CopyObjectArgs.builder()
                                .bucket(bucket)
                                .object(newKey)
                                .source(
                                        CopySource.builder()
                                                .bucket(bucket)
                                                .object(oldKey)
                                                .build()
                                )
                                .build()
                );

                minioClient.removeObject(
                        RemoveObjectArgs.builder()
                                .bucket(bucket)
                                .object(oldKey)
                                .build()
                );
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to rename folder prefix from " + oldPrefix + " to " + newPrefix, e);
        }
    }
}
