package kakha.kudava.filedrivespring.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.minio.*;
import io.minio.messages.Item;
import jakarta.transaction.Transactional;
import kakha.kudava.filedrivespring.enums.EntityType;
import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import kakha.kudava.filedrivespring.repository.FolderRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class MoveService {


    private final MinioClient minioClient;
    private final String bucket;
    private final FileMetaDataRepository fileMetaDataRepository;
    private final FolderRepository folderRepository;
    private final LogsService logsService;
    private final ObjectMapper objectMapper;
    private final ResourceAccessService access;
    private final SharingService sharingService;

    public MoveService(MinioClient minioClient, @Value("${s3.bucket}") String bucket, FileMetaDataRepository fileMetaDataRepository,
                       FolderRepository folderRepository, LogsService logsService, ObjectMapper objectMapper, ResourceAccessService access, SharingService sharingService) {
        this.minioClient = minioClient;
        this.bucket = bucket;
        this.fileMetaDataRepository = fileMetaDataRepository;
        this.folderRepository = folderRepository;
        this.logsService = logsService;
        this.objectMapper = objectMapper;
        this.access = access;
        this.sharingService = sharingService;
    }

    @Transactional
    public FileMetaData copyFile(Long fileId, Long targetFolderId) {
        FileMetaData fileMeta = access.requireFileView(fileId);
        Folders targetFolder = access.requireFolderEdit(targetFolderId);

        String oldKey = fileMeta.getObjectKey();

        String prefix = targetFolder.getPrefix();
        if (!prefix.endsWith("/")) {
            prefix += "/";
        }

        String newKey = prefix + UUID.randomUUID() + "-" + fileMeta.getFileName();

        boolean objectCopied = false;

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

            objectCopied = true;

            FileMetaData newFile = new FileMetaData();
            newFile.setObjectKey(newKey);
            newFile.setFileName(fileMeta.getFileName());
            newFile.setSize(fileMeta.getSize());
            newFile.setDeleted(false);
            newFile.setPermanentlyDeleted(false);
            newFile.setChecksum(fileMeta.getChecksum());
            newFile.setParent(targetFolder);

            /*
             * Copied file belongs to the destination folder owner.
             */
            newFile.setOwner(targetFolder.getOwner());

            newFile.setObjectType(fileMeta.getObjectType());

            FileMetaData savedFile = fileMetaDataRepository.save(newFile);

            Map<String, Object> detailsMap = new LinkedHashMap<>();
            detailsMap.put("fileName", fileMeta.getFileName());
            detailsMap.put("sourceFileId", fileMeta.getId());
            detailsMap.put("newFileId", savedFile.getId());
            detailsMap.put("targetFolder", targetFolder.getPrefix());
            detailsMap.put("targetFolderId", targetFolder.getId());
            detailsMap.put("newOwnerId", targetFolder.getOwner() != null ? targetFolder.getOwner().getId() : null);

            String detailsJson = objectMapper.writeValueAsString(detailsMap);

            logsService.copyLog(
                    fileMeta.getFileName(),
                    fileMeta.getId(),
                    "FILE",
                    detailsJson
            );

            return savedFile;

        } catch (Exception e) {
            if (objectCopied) {
                try {
                    minioClient.removeObject(
                            RemoveObjectArgs.builder()
                                    .bucket(bucket)
                                    .object(newKey)
                                    .build()
                    );
                } catch (Exception ignored) {
                }
            }

            throw new RuntimeException("Copy failed", e);
        }
    }


    @Transactional
    public FileMetaData moveFile(Long fileId, Long targetFolderId) {
        FileMetaData fileMeta = access.requireFileOwner(fileId);
        Folders targetFolder = access.requireFolderOwner(targetFolderId);

        Folders currentFolder = fileMeta.getParent();
        if (currentFolder == null) {
            throw new RuntimeException("File has no parent folder");
        }

        String oldKey = fileMeta.getObjectKey();
        String oldFolder = currentFolder.getPrefix();
        Long oldFolderId = currentFolder.getId();


        String prefix = targetFolder.getPrefix();
        if (!prefix.endsWith("/")) prefix += "/";

        String newKey = prefix + UUID.randomUUID() + "-" + fileMeta.getFileName();

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

            fileMeta.setObjectKey(newKey);
            fileMeta.setParent(targetFolder);

            Map<String, Object> detailsMap = new LinkedHashMap<>();
            detailsMap.put("fileName", fileMeta.getFileName());
            detailsMap.put("oldFolder", oldFolder);
            detailsMap.put("oldFolderId", oldFolderId);
            detailsMap.put("targetFolder", targetFolder.getPrefix());
            detailsMap.put("targetFolderId", targetFolder.getId());

            FileMetaData saved = fileMetaDataRepository.save(fileMeta);

            String detailsJson = objectMapper.writeValueAsString(detailsMap);

            logsService.moveLog(
                    fileMeta.getFileName(),
                    fileMeta.getId(),
                    "FILE",
                    detailsJson
            );

            return saved;

        } catch (Exception e) {
            throw new RuntimeException("Move failed", e);
        }
    }

    @Transactional
    public void moveFolder(Long folderId, Long targetFolderId) {
        Folders folder = access.requireFolderOwner(folderId);
        Folders target = access.requireFolderOwner(targetFolderId);

        String oldPrefix = normalize(folder.getPrefix());
        Long oldFolderId = folder.getParent() != null
                ? folder.getParent().getId()
                : null;
        String newPrefix = normalize(target.getPrefix()) + folder.getName() + "/";

        folderRepository
                .findByPrefixAndOwnerAndDeletedFalseAndPermanentlyDeletedFalse(
                        newPrefix,
                        target.getOwner()
                )
                .ifPresent(existing -> {
                    throw new RuntimeException("Folder already exists in target: " + folder.getName());
                });

        if (folder.getParent() == null) {
            throw new RuntimeException("Root folder cannot be moved");
        }

        if (folder.getId().equals(target.getId())) {
            throw new RuntimeException("Cannot move folder into itself");
        }

        if (isDescendantOf(target, folder)) {
            throw new RuntimeException("Cannot move folder into one of its own subfolders");
        }

        try {
            Iterable<Result<Item>> objects = minioClient.listObjects(
                    ListObjectsArgs.builder()
                            .bucket(bucket)
                            .prefix(oldPrefix)
                            .recursive(true)
                            .build()
            );

            for (Result<Item> r : objects) {
                Item item = r.get();
                String oldKey = item.objectName();

                String newKey = newPrefix + oldKey.substring(oldPrefix.length());

                // copy
                minioClient.copyObject(
                        CopyObjectArgs.builder()
                                .bucket(bucket)
                                .object(newKey)
                                .source(CopySource.builder()
                                        .bucket(bucket)
                                        .object(oldKey)
                                        .build())
                                .build()
                );

                // delete old
                minioClient.removeObject(
                        RemoveObjectArgs.builder()
                                .bucket(bucket)
                                .object(oldKey)
                                .build()
                );

                fileMetaDataRepository.findByObjectKey(oldKey)
                        .ifPresent(file -> {
                            file.setObjectKey(newKey);
                            fileMetaDataRepository.save(file);
                        });
            }

            updateFolderPrefixes(folder, oldPrefix, newPrefix, target);

            Map<String, Object> detailsMap = new LinkedHashMap<>();
            detailsMap.put("folderName", folder.getName());
            detailsMap.put("oldFolder", oldPrefix);
            detailsMap.put("oldFolderId", oldFolderId);
            detailsMap.put("targetFolder", target.getPrefix());
            detailsMap.put("targetFolderId", target.getId());

            logsService.moveLog(
                    folder.getName(),
                    folder.getId(),
                    "FOLDER",
                    objectMapper.writeValueAsString(detailsMap)
            );

        } catch (Exception e) {
            throw new RuntimeException("Folder move failed", e);
        }
    }


    private boolean isDescendantOf(Folders possibleChild, Folders possibleParent) {
        Folders current = possibleChild;

        while (current != null) {
            if (current.getId() != null && current.getId().equals(possibleParent.getId())) {
                return true;
            }

            current = current.getParent();
        }

        return false;
    }
    private void updateFolderPrefixes(Folders folder,
                                      String oldPrefix,
                                      String newPrefix,
                                      Folders newParent) {

        String currentPrefix = normalize(folder.getPrefix());

        if (!currentPrefix.startsWith(oldPrefix)) {
            throw new RuntimeException("Folder prefix does not start with old prefix");
        }

        String updatedPrefix = newPrefix + currentPrefix.substring(oldPrefix.length());

        folder.setPrefix(updatedPrefix);
        folder.setParent(newParent);
        folderRepository.save(folder);

        if (folder.getChildren() != null) {
            for (Folders child : folder.getChildren()) {
                updateFolderPrefixes(child, oldPrefix, newPrefix, folder);
            }
        }
    }

    @Transactional
    public Folders copyFolder(Long folderId, Long targetFolderId) {
        Folders sourceFolder = access.requireFolderView(folderId);
        Folders targetFolder = access.requireFolderEdit(targetFolderId);

        if (sourceFolder.getId().equals(targetFolder.getId())) {
            throw new RuntimeException("Cannot copy folder into itself");
        }

        if (isDescendantOf(targetFolder, sourceFolder)) {
            throw new RuntimeException("Cannot copy folder into one of its own subfolders");
        }

        String targetPrefix = normalizePrefix(targetFolder.getPrefix());
        String newRootPrefix = targetPrefix + sourceFolder.getName() + "/";

        folderRepository
                .findByPrefixAndOwnerAndDeletedFalseAndPermanentlyDeletedFalse(
                        newRootPrefix,
                        targetFolder.getOwner()
                )
                .ifPresent(existing -> {
                    throw new RuntimeException("Folder already exists in target: " + sourceFolder.getName());
                });

        try {
            Folders copiedRoot = copyFolderRecursive(sourceFolder, targetFolder, newRootPrefix);

            Map<String, Object> detailsMap = new LinkedHashMap<>();
            detailsMap.put("folderName", sourceFolder.getName());
            detailsMap.put("targetFolder", targetFolder.getPrefix());
            detailsMap.put("targetFolderId", targetFolder.getId());

            String detailsJson = objectMapper.writeValueAsString(detailsMap);

            logsService.copyLog(
                    sourceFolder.getName(),
                    sourceFolder.getId(),
                    "FOLDER",
                    detailsJson
            );

            return copiedRoot;

        } catch (Exception e) {
            throw new RuntimeException("Folder copy failed", e);
        }
    }

    private Folders copyFolderRecursive(Folders sourceFolder, Folders newParent, String newPrefix) throws Exception {
        User user = access.currentUser();

        Folders copiedFolder = new Folders();
        copiedFolder.setName(sourceFolder.getName());
        copiedFolder.setPrefix(newPrefix);
        copiedFolder.setDeleted(false);
        copiedFolder.setPermanentlyDeleted(false);
        copiedFolder.setParent(newParent);
        copiedFolder.setOwner(newParent.getOwner());

        copiedFolder = folderRepository.save(copiedFolder);

        List<FileMetaData> files = fileMetaDataRepository.findAllByParentId(sourceFolder.getId())
                .stream()
                .filter(file -> !file.isDeleted())
                .filter(file -> !file.isPermanentlyDeleted())
                .filter(file -> sharingService.canViewFile(file, user))
                .toList();

        for (FileMetaData sourceFile : files) {
            String oldKey = sourceFile.getObjectKey();
            String newKey = normalizePrefix(newPrefix) + UUID.randomUUID() + "-" + sourceFile.getFileName();

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

            FileMetaData copiedFile = new FileMetaData();
            copiedFile.setObjectKey(newKey);
            copiedFile.setFileName(sourceFile.getFileName());
            copiedFile.setSize(sourceFile.getSize());
            copiedFile.setDeleted(false);
            copiedFile.setPermanentlyDeleted(false);
            copiedFile.setChecksum(sourceFile.getChecksum());
            copiedFile.setParent(copiedFolder);

            /*
             * Copied file belongs to the copied folder owner.
             */
            copiedFile.setOwner(copiedFolder.getOwner());

            copiedFile.setObjectType(sourceFile.getObjectType());

            FileMetaData savedFile = fileMetaDataRepository.save(copiedFile);

            Map<String, Object> fileDetailsMap = new LinkedHashMap<>();
            fileDetailsMap.put("fileName", sourceFile.getFileName());
            fileDetailsMap.put("sourceFileId", sourceFile.getId());
            fileDetailsMap.put("newFileId", savedFile.getId());
            fileDetailsMap.put("targetFolder", copiedFolder.getPrefix());
            fileDetailsMap.put("targetFolderId", copiedFolder.getId());

            String fileDetailsJson = objectMapper.writeValueAsString(fileDetailsMap);

            logsService.copyLog(
                    sourceFile.getFileName(),
                    sourceFile.getId(),
                    "FILE",
                    fileDetailsJson
            );
        }

        if (sourceFolder.getChildren() != null) {
            for (Folders child : sourceFolder.getChildren()) {
                if (child.isDeleted() || child.isPermanentlyDeleted()) {
                    continue;
                }

                if (!sharingService.canViewFolder(child, user)) {
                    continue;
                }

                String childPrefix = normalizePrefix(newPrefix) + child.getName() + "/";
                copyFolderRecursive(child, copiedFolder, childPrefix);
            }
        }

        return copiedFolder;
    }

    private String normalizePrefix(String prefix) {
        if (prefix == null || prefix.isBlank()) {
            return "";
        }
        return prefix.endsWith("/") ? prefix : prefix + "/";
    }
    private String normalize(String prefix) {
        if (!prefix.endsWith("/")) return prefix + "/";
        return prefix;
    }
}
