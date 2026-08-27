package kakha.kudava.filedrivespring.services;

import kakha.kudava.filedrivespring.dto.*;
import kakha.kudava.filedrivespring.enums.EntityType;
import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import kakha.kudava.filedrivespring.repository.FolderRepository;
import kakha.kudava.filedrivespring.repository.UserRepository;
import kakha.kudava.filedrivespring.services.objects.FolderService;
import kakha.kudava.filedrivespring.services.objects.ObjectStorageService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import kakha.kudava.filedrivespring.enums.DriveSpace;

import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Service
public class TrashcanService {

    private final FileMetaDataRepository fileMetaDataRepository;
    private final FolderRepository folderRepository;
    private final UserRepository userRepository;
    private final ObjectStorageService objectStorageService;
    private final FolderService folderService;
    private final LogsService logsService;

    public TrashcanService(
            FileMetaDataRepository fileMetaDataRepository,
            FolderRepository folderRepository,
            UserRepository userRepository,
            ObjectStorageService objectStorageService,
            FolderService folderService, LogsService logsService
    ) {
        this.fileMetaDataRepository = fileMetaDataRepository;
        this.folderRepository = folderRepository;
        this.userRepository = userRepository;
        this.objectStorageService = objectStorageService;
        this.folderService = folderService;
        this.logsService = logsService;
    }

    public ViewTrashcanDTO viewTrashcan() {
        User user = currentUser();

        List<TrashFileDTO> deletedFiles =
                fileMetaDataRepository.findByOwnerAndDeletedTrueAndPermanentlyDeletedFalse(user)
                        .stream()
                        .map(file -> new TrashFileDTO(
                                file.getId(),
                                file.getFileName(),
                                file.getObjectType(),
                                file.getSize(),
                                file.getCreationDate(),
                                file.getObjectKey(),
                                file.getOriginalObjectKey()
                        ))
                        .toList();

        List<TrashFolderDTO> deletedFolders =
                folderRepository.findByOwnerAndDeletedTrueAndPermanentlyDeletedFalse(user)
                        .stream()
                        .map(folder -> new TrashFolderDTO(
                                folder.getId(),
                                folder.getName(),
                                folder.getPrefix()
                        ))
                        .toList();

        return new ViewTrashcanDTO(deletedFiles, deletedFolders);
    }

    @Transactional
    public void moveToTrash(MoveToTrashReqDTO req) throws Exception {
        if (req == null) {
            throw new IllegalArgumentException("Request body is required");
        }

        List<Long> fileIds = safeIds(req.getFileIds());
        List<Long> folderIds = safeIds(req.getFolderIds());

        if (fileIds.isEmpty() && folderIds.isEmpty()) {
            throw new IllegalArgumentException("No files or folders provided");
        }

        if (!fileIds.isEmpty()) {
            objectStorageService.deleteMultipleFiles(fileIds);
        }

        if (!folderIds.isEmpty()) {
            folderService.deleteMultiple(folderIds);
        }
    }

    @Transactional
    public void deletePermanently(TrashcanActionRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Request body is required");
        }

        User user = currentUser();

        List<Long> fileIds = safeIds(request.getFileIds());
        List<Long> folderIds = safeIds(request.getFolderIds());

        if (fileIds.isEmpty() && folderIds.isEmpty()) {
            throw new IllegalArgumentException("No files or folders provided");
        }

        deleteFilesPermanently(fileIds, user);
        deleteFoldersPermanently(folderIds, user);
    }

    private void deleteFilesPermanently(List<Long> fileIds, User user) {
        if (fileIds == null || fileIds.isEmpty()) {
            return;
        }

        List<FileMetaData> filesToDelete = new ArrayList<>();

        for (Long fileId : fileIds) {
            FileMetaData file = fileMetaDataRepository
                    .findByIdAndDeletedTrueAndPermanentlyDeletedFalseAndOwner(fileId, user)
                    .orElseThrow(() -> new RuntimeException("Trashed file not found or access denied: " + fileId));

            if (file.getObjectKey() == null || file.getObjectKey().isBlank()) {
                throw new RuntimeException("Trashed file has no trash object key: " + fileId);
            }

            filesToDelete.add(file);
        }

        Instant now = Instant.now();

        for (FileMetaData file : filesToDelete) {
            String trashObjectKey = file.getObjectKey();

            objectStorageService.deleteTrashObject(trashObjectKey);

            file.setPermanentlyDeleted(true);
            file.setPermanentlyDeletedAt(now);

            String detailsJson = """
            {
              "name": "%s",
              "trashObjectKey": "%s",
              "originalObjectKey": "%s",
              "deletedAt": "%s",
              "permanentlyDeletedAt": "%s",
              "source": "manual_permanent_delete"
            }
            """.formatted(
                    file.getFileName(),
                    trashObjectKey,
                    file.getOriginalObjectKey(),
                    file.getDeletedAt(),
                    now
            );

            logsService.permanentDeleteLog(
                    file.getFileName(),
                    file.getId(),
                    EntityType.FILE.name(),
                    detailsJson
            );
        }

        fileMetaDataRepository.saveAll(filesToDelete);
    }

    private void deleteFoldersPermanently(List<Long> folderIds, User user) {
        if (folderIds == null || folderIds.isEmpty()) {
            return;
        }

        List<Folders> selectedFolders = new ArrayList<>();

        for (Long folderId : folderIds) {
            Folders folder = folderRepository
                    .findByIdAndDeletedTrueAndPermanentlyDeletedFalseAndOwner(folderId, user)
                    .orElseThrow(() -> new RuntimeException("Trashed folder not found or access denied: " + folderId));

            selectedFolders.add(folder);
        }

        List<Folders> topLevelFolders = getTopLevelFolders(selectedFolders);

        List<FileMetaData> allFilesToDelete = new ArrayList<>();
        List<Folders> allFoldersToDelete = new ArrayList<>();
        List<String> trashPrefixesToDelete = new ArrayList<>();

        Set<Long> seenFileIds = new HashSet<>();
        Set<Long> seenFolderIds = new HashSet<>();

        Map<Long, String> rootTrashPrefixByFolderId = new HashMap<>();

        for (Folders folder : topLevelFolders) {
            String originalPrefix = normalizePrefix(folder.getPrefix());
            String trashPrefix = "users/" + user.getId() + "/folders/" + folder.getId() + "/";

            trashPrefixesToDelete.add(trashPrefix);

            List<FileMetaData> filesInFolder = fileMetaDataRepository
                    .findByOwnerAndDeletedTrueAndPermanentlyDeletedFalseAndOriginalObjectKeyStartingWith(
                            user,
                            originalPrefix
                    );

            List<Folders> foldersInSubtree = folderRepository
                    .findByOwnerAndDeletedTrueAndPermanentlyDeletedFalseAndPrefixStartingWith(
                            user,
                            originalPrefix
                    );

            for (FileMetaData file : filesInFolder) {
                if (file.getId() != null && seenFileIds.add(file.getId())) {
                    allFilesToDelete.add(file);
                }
            }

            for (Folders subtreeFolder : foldersInSubtree) {
                if (subtreeFolder.getId() != null && seenFolderIds.add(subtreeFolder.getId())) {
                    allFoldersToDelete.add(subtreeFolder);
                    rootTrashPrefixByFolderId.put(subtreeFolder.getId(), trashPrefix);
                }
            }
        }

        Instant now = Instant.now();

        for (String trashPrefix : trashPrefixesToDelete) {
            objectStorageService.deleteTrashPrefix(trashPrefix);
        }

        for (FileMetaData file : allFilesToDelete) {
            file.setPermanentlyDeleted(true);
            file.setPermanentlyDeletedAt(now);

            String detailsJson = """
                {
                  "name": "%s",
                  "trashObjectKey": "%s",
                  "originalObjectKey": "%s",
                  "deletedAt": "%s",
                  "permanentlyDeletedAt": "%s",
                  "source": "manual_permanent_delete"
                }
                """.formatted(
                    file.getFileName(),
                    file.getObjectKey(),
                    file.getOriginalObjectKey(),
                    file.getDeletedAt(),
                    now
            );

            logsService.permanentDeleteLog(
                    file.getFileName(),
                    file.getId(),
                    EntityType.FILE.name(),
                    detailsJson
            );
        }

        for (Folders folder : allFoldersToDelete) {
            folder.setPermanentlyDeleted(true);
            folder.setPermanentlyDeletedAt(now);

            String rootTrashPrefix = rootTrashPrefixByFolderId.get(folder.getId());

            String detailsJson = """
                {
                  "name": "%s",
                  "prefix": "%s",
                  "rootTrashPrefix": "%s",
                  "deletedAt": "%s",
                  "permanentlyDeletedAt": "%s",
                  "source": "manual_permanent_delete"
                }
                """.formatted(
                    folder.getName(),
                    folder.getPrefix(),
                    rootTrashPrefix,
                    folder.getDeletedAt(),
                    now
            );

            logsService.permanentDeleteLog(
                    folder.getName(),
                    folder.getId(),
                    EntityType.FOLDER.name(),
                    detailsJson
            );
        }

        if (!allFilesToDelete.isEmpty()) {
            fileMetaDataRepository.saveAll(allFilesToDelete);
        }

        if (!allFoldersToDelete.isEmpty()) {
            folderRepository.saveAll(allFoldersToDelete);
        }
    }

    @Transactional
    public void clearTrash() {
        User user = currentUser();

        List<FileMetaData> filesToClear = fileMetaDataRepository
                .findByOwnerAndDeletedTrueAndPermanentlyDeletedFalse(user);

        List<Folders> foldersToClear = folderRepository
                .findByOwnerAndDeletedTrueAndPermanentlyDeletedFalse(user);

        if (filesToClear.isEmpty() && foldersToClear.isEmpty()) {
            return;
        }

        Instant now = Instant.now();

        String clearDetailsJson = """
        {
          "fileCount": %d,
          "folderCount": %d,
          "clearedAt": "%s"
        }
        """.formatted(
                filesToClear.size(),
                foldersToClear.size(),
                now
        );

        logsService.clearTrashLog(clearDetailsJson);

        for (FileMetaData file : filesToClear) {
            String trashObjectKey = file.getObjectKey();

            if (trashObjectKey != null && !trashObjectKey.isBlank()) {
                objectStorageService.deleteTrashObject(trashObjectKey);
            }

            file.setPermanentlyDeleted(true);
            file.setPermanentlyDeletedAt(now);

            String detailsJson = """
            {
              "name": "%s",
              "trashObjectKey": "%s",
              "originalObjectKey": "%s",
              "deletedAt": "%s",
              "permanentlyDeletedAt": "%s",
              "source": "clear_trash"
            }
            """.formatted(
                    file.getFileName(),
                    trashObjectKey,
                    file.getOriginalObjectKey(),
                    file.getDeletedAt(),
                    now
            );

            logsService.permanentDeleteLog(
                    file.getFileName(),
                    file.getId(),
                    EntityType.FILE.name(),
                    detailsJson
            );
        }

        for (Folders folder : foldersToClear) {
            String trashPrefix = "users/" + user.getId() + "/folders/" + folder.getId() + "/";

            objectStorageService.deleteTrashPrefix(trashPrefix);

            folder.setPermanentlyDeleted(true);
            folder.setPermanentlyDeletedAt(now);

            String detailsJson = """
            {
              "name": "%s",
              "prefix": "%s",
              "trashPrefix": "%s",
              "deletedAt": "%s",
              "permanentlyDeletedAt": "%s",
              "source": "clear_trash"
            }
            """.formatted(
                    folder.getName(),
                    folder.getPrefix(),
                    trashPrefix,
                    folder.getDeletedAt(),
                    now
            );

            logsService.permanentDeleteLog(
                    folder.getName(),
                    folder.getId(),
                    EntityType.FOLDER.name(),
                    detailsJson
            );
        }

        fileMetaDataRepository.saveAll(filesToClear);
        folderRepository.saveAll(foldersToClear);
    }
    @Transactional
    public void restore(TrashcanActionRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("Request body is required");
        }

        User user = currentUser();

        List<Long> fileIds = safeIds(request.getFileIds());
        List<Long> folderIds = safeIds(request.getFolderIds());

        if (fileIds.isEmpty() && folderIds.isEmpty()) {
            throw new IllegalArgumentException("No files or folders provided");
        }

        Set<Long> filesRestoredByFolders = restoreFolders(folderIds, user);

        List<Long> remainingFileIds = fileIds.stream()
                .filter(fileId -> !filesRestoredByFolders.contains(fileId))
                .toList();

        restoreFiles(remainingFileIds, user);
    }

    private void restoreFiles(List<Long> fileIds, User user) {
        if (fileIds == null || fileIds.isEmpty()) {
            return;
        }

        List<FileMetaData> filesToSave = new ArrayList<>();

        for (Long fileId : fileIds) {
            FileMetaData file = fileMetaDataRepository
                    .findByIdAndDeletedTrueAndPermanentlyDeletedFalseAndOwner(fileId, user)
                    .orElseThrow(() -> new RuntimeException("Trashed file not found or access denied: " + fileId));

            if (file.getObjectKey() == null || file.getObjectKey().isBlank()) {
                throw new RuntimeException("Trashed file has no trash object key: " + fileId);
            }

            String trashObjectKey = file.getObjectKey();
            String originalObjectKey = file.getOriginalObjectKey();

            if (originalObjectKey == null || originalObjectKey.isBlank()) {
                throw new RuntimeException("Trashed file has no original object key: " + fileId);
            }

            Folders restoreParent =
                    resolveExistingRestoreParent(
                            originalObjectKey,
                            user,
                            file.getDriveSpace()
                    );
            String restoredObjectKey = normalizePrefix(restoreParent.getPrefix()) + file.getFileName();

            if (fileMetaDataRepository.existsByObjectKeyAndDeletedFalseAndPermanentlyDeletedFalse(restoredObjectKey)) {
                throw new RuntimeException("A file already exists at restore destination: " + restoredObjectKey);
            }

            objectStorageService.restoreTrashObject(trashObjectKey, restoredObjectKey);

            String detailsJson = """
            {
              "name": "%s",
              "trashObjectKey": "%s",
              "restoredObjectKey": "%s",
              "originalObjectKey": "%s",
              "restoredParentId": %d
            }
            """.formatted(
                    file.getFileName(),
                    trashObjectKey,
                    restoredObjectKey,
                    originalObjectKey,
                    restoreParent.getId()
            );

            logsService.restoreFromTrashLog(
                    file.getFileName(),
                    file.getId(),
                    EntityType.FILE.name(),
                    detailsJson
            );

            file.setParent(restoreParent);
            file.setObjectKey(restoredObjectKey);
            file.setOriginalObjectKey(null);
            file.setDeleted(false);
            file.setDeletedAt(null);
            file.setPermanentlyDeleted(false);
            file.setPermanentlyDeletedAt(null);

            filesToSave.add(file);
        }

        if (!filesToSave.isEmpty()) {
            fileMetaDataRepository.saveAll(filesToSave);
        }
    }

    private Set<Long> restoreFolders(List<Long> folderIds, User user) {
        Set<Long> restoredFileIds = new HashSet<>();

        if (folderIds == null || folderIds.isEmpty()) {
            return restoredFileIds;
        }

        List<Folders> selectedFolders = new ArrayList<>();

        for (Long folderId : folderIds) {
            Folders folder = folderRepository
                    .findByIdAndDeletedTrueAndPermanentlyDeletedFalseAndOwner(folderId, user)
                    .orElseThrow(() -> new RuntimeException("Trashed folder not found or access denied: " + folderId));

            selectedFolders.add(folder);
        }

        List<Folders> topLevelFolders = getTopLevelFolders(selectedFolders);

        for (Folders folder : topLevelFolders) {
            restoredFileIds.addAll(restoreOneFolder(folder, user));
        }

        return restoredFileIds;
    }

    private Set<Long> restoreOneFolder(Folders folder, User user) {
        Set<Long> restoredFileIds = new HashSet<>();

        String oldRootPrefix = normalizePrefix(folder.getPrefix());

        if (oldRootPrefix.isBlank()) {
            throw new RuntimeException("Trashed folder has no original prefix: " + folder.getId());
        }

        Folders restoreParent =
                resolveExistingRestoreParent(
                        oldRootPrefix,
                        user,
                        folder.getDriveSpace()
                );
        String newRootPrefix = normalizePrefix(restoreParent.getPrefix()) + folder.getName() + "/";

        folderRepository
                .findByPrefixAndOwnerAndDeletedFalseAndPermanentlyDeletedFalse(newRootPrefix, user)
                .ifPresent(existing -> {
                    throw new RuntimeException("A folder already exists at restore destination: " + newRootPrefix);
                });

        List<Folders> foldersInSubtree = folderRepository
                .findByOwnerAndDeletedTrueAndPermanentlyDeletedFalseAndPrefixStartingWith(user, oldRootPrefix);

        List<FileMetaData> filesInSubtree = fileMetaDataRepository
                .findByOwnerAndDeletedTrueAndPermanentlyDeletedFalseAndOriginalObjectKeyStartingWith(
                        user,
                        oldRootPrefix
                );

        foldersInSubtree.sort(
                Comparator.comparingInt(f -> normalizePrefix(f.getPrefix()).length())
        );

        Map<Long, String> oldPrefixByFolderId = new HashMap<>();
        Map<String, Folders> folderByOldPrefix = new HashMap<>();
        Map<String, String> newPrefixByOldPrefix = new HashMap<>();

        for (Folders subtreeFolder : foldersInSubtree) {
            String oldPrefix = normalizePrefix(subtreeFolder.getPrefix());
            String relativePrefix = relativePath(oldRootPrefix, oldPrefix);
            String newPrefix = normalizePrefix(newRootPrefix + relativePrefix);

            folderRepository
                    .findByPrefixAndOwnerAndDeletedFalseAndPermanentlyDeletedFalse(newPrefix, user)
                    .ifPresent(existing -> {
                        throw new RuntimeException("A folder already exists at restore destination: " + newPrefix);
                    });

            oldPrefixByFolderId.put(subtreeFolder.getId(), oldPrefix);
            folderByOldPrefix.put(oldPrefix, subtreeFolder);
            newPrefixByOldPrefix.put(oldPrefix, newPrefix);
        }

        for (FileMetaData file : filesInSubtree) {
            String originalObjectKey = file.getOriginalObjectKey();

            if (originalObjectKey == null || originalObjectKey.isBlank()) {
                throw new RuntimeException("Trashed file has no original object key: " + file.getId());
            }

            String relativeObjectKey = relativePath(oldRootPrefix, originalObjectKey);
            String restoredObjectKey = newRootPrefix + relativeObjectKey;

            if (fileMetaDataRepository.existsByObjectKeyAndDeletedFalseAndPermanentlyDeletedFalse(restoredObjectKey)) {
                throw new RuntimeException("A file already exists at restore destination: " + restoredObjectKey);
            }
        }

        for (Folders subtreeFolder : foldersInSubtree) {
            String oldPrefix = oldPrefixByFolderId.get(subtreeFolder.getId());
            String newPrefix = newPrefixByOldPrefix.get(oldPrefix);

            String oldParentPrefix = parentPrefixOf(oldPrefix);
            Folders newParent = folderByOldPrefix.get(oldParentPrefix);

            if (newParent == null) {
                newParent = restoreParent;
            }

            String folderDetailsJson = """
                {
                  "name": "%s",
                  "oldPrefix": "%s",
                  "newPrefix": "%s",
                  "restoredParentId": %d
                }
                """.formatted(
                    subtreeFolder.getName(),
                    oldPrefix,
                    newPrefix,
                    newParent.getId()
            );

            logsService.restoreFromTrashLog(
                    subtreeFolder.getName(),
                    subtreeFolder.getId(),
                    EntityType.FOLDER.name(),
                    folderDetailsJson
            );

            subtreeFolder.setParent(newParent);
            subtreeFolder.setPrefix(newPrefix);
            subtreeFolder.setDeleted(false);
            subtreeFolder.setDeletedAt(null);
            subtreeFolder.setPermanentlyDeleted(false);
            subtreeFolder.setPermanentlyDeletedAt(null);
        }

        if (!foldersInSubtree.isEmpty()) {
            folderRepository.saveAll(foldersInSubtree);
        }

        Map<String, Folders> restoredFolderByNewPrefix = new HashMap<>();

        for (Folders restoredFolder : foldersInSubtree) {
            restoredFolderByNewPrefix.put(normalizePrefix(restoredFolder.getPrefix()), restoredFolder);
        }

        List<FileMetaData> filesToSave = new ArrayList<>();

        for (FileMetaData file : filesInSubtree) {
            String trashObjectKey = file.getObjectKey();
            String originalObjectKey = file.getOriginalObjectKey();

            String relativeObjectKey = relativePath(oldRootPrefix, originalObjectKey);
            String restoredObjectKey = newRootPrefix + relativeObjectKey;

            String originalParentPrefix = parentPrefixOf(originalObjectKey);
            String relativeParentPrefix = relativePath(oldRootPrefix, originalParentPrefix);
            String restoredParentPrefix = normalizePrefix(newRootPrefix + relativeParentPrefix);

            Folders restoredParent = restoredFolderByNewPrefix.get(restoredParentPrefix);

            if (restoredParent == null) {
                restoredParent = restoreParent;
            }

            objectStorageService.restoreTrashObject(trashObjectKey, restoredObjectKey);

            String fileDetailsJson = """
                {
                  "name": "%s",
                  "trashObjectKey": "%s",
                  "restoredObjectKey": "%s",
                  "originalObjectKey": "%s",
                  "restoredParentId": %d
                }
                """.formatted(
                    file.getFileName(),
                    trashObjectKey,
                    restoredObjectKey,
                    originalObjectKey,
                    restoredParent.getId()
            );

            logsService.restoreFromTrashLog(
                    file.getFileName(),
                    file.getId(),
                    EntityType.FILE.name(),
                    fileDetailsJson
            );

            file.setParent(restoredParent);
            file.setObjectKey(restoredObjectKey);
            file.setOriginalObjectKey(null);
            file.setDeleted(false);
            file.setDeletedAt(null);
            file.setPermanentlyDeleted(false);
            file.setPermanentlyDeletedAt(null);

            filesToSave.add(file);
            restoredFileIds.add(file.getId());
        }

        if (!filesToSave.isEmpty()) {
            fileMetaDataRepository.saveAll(filesToSave);
        }

        return restoredFileIds;
    }

    private Folders resolveExistingRestoreParent(
            String originalPath,
            User user,
            DriveSpace driveSpace
    ) {
        Objects.requireNonNull(user, "user");
        Objects.requireNonNull(driveSpace, "driveSpace");

        String parentPrefix = parentPrefixOf(originalPath);

        while (parentPrefix != null && !parentPrefix.isBlank()) {
            Optional<Folders> folder = folderRepository
                    .findByPrefixAndOwnerAndDriveSpaceAndDeletedFalseAndPermanentlyDeletedFalse(
                            parentPrefix,
                            user,
                            driveSpace
                    );

            if (folder.isPresent()) {
                return folder.get();
            }

            parentPrefix = parentPrefixOf(parentPrefix);
        }

        return folderRepository
                .findByOwnerAndParentIsNullAndDriveSpaceAndDeletedFalseAndPermanentlyDeletedFalse(
                        user,
                        driveSpace
                )
                .orElseThrow(() -> new RuntimeException(
                        driveSpace + " root folder not found"
                ));
    }

    private List<Folders> getTopLevelFolders(List<Folders> folders) {
        if (folders == null || folders.isEmpty()) {
            return List.of();
        }

        List<Folders> sorted = new ArrayList<>(folders);

        sorted.sort(
                Comparator.comparingInt(folder -> normalizePrefix(folder.getPrefix()).length())
        );

        List<Folders> topLevel = new ArrayList<>();

        for (Folders candidate : sorted) {
            String candidatePrefix = normalizePrefix(candidate.getPrefix());

            boolean insideAlreadySelectedFolder = false;

            for (Folders selected : topLevel) {
                String selectedPrefix = normalizePrefix(selected.getPrefix());

                if (!candidatePrefix.equals(selectedPrefix) && candidatePrefix.startsWith(selectedPrefix)) {
                    insideAlreadySelectedFolder = true;
                    break;
                }
            }

            if (!insideAlreadySelectedFolder) {
                topLevel.add(candidate);
            }
        }

        return topLevel;
    }

    private List<Long> safeIds(List<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return List.of();
        }

        Set<Long> uniqueIds = new LinkedHashSet<>();

        for (Long id : ids) {
            if (id != null) {
                uniqueIds.add(id);
            }
        }

        return new ArrayList<>(uniqueIds);
    }

    private String normalizePrefix(String prefix) {
        if (prefix == null || prefix.isBlank()) {
            return "";
        }

        String normalized = prefix.trim().replace("\\", "/");

        if (!normalized.endsWith("/")) {
            normalized += "/";
        }

        return normalized;
    }

    private String parentPrefixOf(String path) {
        if (path == null || path.isBlank()) {
            return "";
        }

        String normalized = path.trim().replace("\\", "/");

        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }

        int lastSlash = normalized.lastIndexOf("/");

        if (lastSlash < 0) {
            return "";
        }

        return normalized.substring(0, lastSlash + 1);
    }

    private String relativePath(String basePrefix, String fullPath) {
        String normalizedBase = normalizePrefix(basePrefix);

        String normalizedFull = fullPath == null
                ? ""
                : fullPath.trim().replace("\\", "/");

        if (normalizedFull.startsWith(normalizedBase)) {
            return normalizedFull.substring(normalizedBase.length());
        }

        return normalizedFull;
    }

    private User currentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || authentication.getName() == null) {
            throw new RuntimeException("Not authenticated");
        }

        return userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new RuntimeException("Authenticated user not found"));
    }

    @Transactional
    public void permanentlyDeleteTrashOlderThan(Duration maxAge) {
        if (maxAge == null || maxAge.isNegative() || maxAge.isZero()) {
            throw new IllegalArgumentException("maxAge must be positive");
        }

        Instant cutoff = Instant.now().minus(maxAge);

        List<FileMetaData> oldFiles = fileMetaDataRepository
                .findByDeletedTrueAndPermanentlyDeletedFalseAndDeletedAtBefore(cutoff);

        List<Folders> oldFolders = folderRepository
                .findByDeletedTrueAndPermanentlyDeletedFalseAndDeletedAtBefore(cutoff);

        if (oldFiles.isEmpty() && oldFolders.isEmpty()) {
            return;
        }

        Instant now = Instant.now();

        Set<Long> fileIdsHandledByFolders = new HashSet<>();

        List<Folders> topLevelOldFolders = getTopLevelFolders(oldFolders);

        for (Folders folder : topLevelOldFolders) {
            User owner = folder.getOwner();

            if (owner == null) {
                continue;
            }

            String originalPrefix = normalizePrefix(folder.getPrefix());

            if (originalPrefix.isBlank()) {
                continue;
            }

            String trashPrefix = "users/" + owner.getId() + "/folders/" + folder.getId() + "/";

            List<FileMetaData> filesInFolder = fileMetaDataRepository
                    .findByOwnerAndDeletedTrueAndPermanentlyDeletedFalseAndOriginalObjectKeyStartingWith(
                            owner,
                            originalPrefix
                    );

            List<Folders> foldersInSubtree = folderRepository
                    .findByOwnerAndDeletedTrueAndPermanentlyDeletedFalseAndPrefixStartingWith(
                            owner,
                            originalPrefix
                    );

            objectStorageService.deleteTrashPrefix(trashPrefix);

            for (FileMetaData file : filesInFolder) {
                file.setPermanentlyDeleted(true);
                file.setPermanentlyDeletedAt(now);
                fileIdsHandledByFolders.add(file.getId());

                String detailsJson = """
                    {
                      "reason": "older_than_max_age",
                      "deletedAt": "%s",
                      "permanentlyDeletedAt": "%s",
                      "maxAgeSeconds": %d,
                      "fileName": "%s",
                      "trashObjectKey": "%s",
                      "originalObjectKey": "%s"
                    }
                    """.formatted(
                        file.getDeletedAt(),
                        now,
                        maxAge.toSeconds(),
                        file.getFileName(),
                        file.getObjectKey(),
                        file.getOriginalObjectKey()
                );

                logsService.trashAutoDeleteLog(
                        owner,
                        file.getId(),
                        EntityType.FILE.name(),
                        detailsJson
                );
            }

            for (Folders subtreeFolder : foldersInSubtree) {
                subtreeFolder.setPermanentlyDeleted(true);
                subtreeFolder.setPermanentlyDeletedAt(now);

                String detailsJson = """
                    {
                      "reason": "older_than_max_age",
                      "deletedAt": "%s",
                      "permanentlyDeletedAt": "%s",
                      "maxAgeSeconds": %d,
                      "folderName": "%s",
                      "originalPrefix": "%s",
                      "trashPrefix": "%s"
                    }
                    """.formatted(
                        subtreeFolder.getDeletedAt(),
                        now,
                        maxAge.toSeconds(),
                        subtreeFolder.getName(),
                        subtreeFolder.getPrefix(),
                        "users/" + owner.getId() + "/folders/" + subtreeFolder.getId() + "/"
                );

                logsService.trashAutoDeleteLog(
                        owner,
                        subtreeFolder.getId(),
                        EntityType.FOLDER.name(),
                        detailsJson
                );
            }

            if (!filesInFolder.isEmpty()) {
                fileMetaDataRepository.saveAll(filesInFolder);
            }

            if (!foldersInSubtree.isEmpty()) {
                folderRepository.saveAll(foldersInSubtree);
            }
        }

        List<FileMetaData> standaloneFilesToDelete = oldFiles.stream()
                .filter(file -> file.getId() != null)
                .filter(file -> !fileIdsHandledByFolders.contains(file.getId()))
                .toList();

        for (FileMetaData file : standaloneFilesToDelete) {
            if (file.getObjectKey() != null && !file.getObjectKey().isBlank()) {
                objectStorageService.deleteTrashObject(file.getObjectKey());
            }

            file.setPermanentlyDeleted(true);
            file.setPermanentlyDeletedAt(now);

            User owner = file.getOwner();
            String detailsJson = """
                {
                  "reason": "older_than_max_age",
                  "deletedAt": "%s",
                  "permanentlyDeletedAt": "%s",
                  "maxAgeSeconds": %d,
                  "fileName": "%s",
                  "trashObjectKey": "%s",
                  "originalObjectKey": "%s"
                }
                """.formatted(
                    file.getDeletedAt(),
                    now,
                    maxAge.toSeconds(),
                    file.getFileName(),
                    file.getObjectKey(),
                    file.getOriginalObjectKey()
            );

            logsService.trashAutoDeleteLog(
                    owner,
                    file.getId(),
                    EntityType.FILE.name(),
                    detailsJson
            );
        }

        if (!standaloneFilesToDelete.isEmpty()) {
            fileMetaDataRepository.saveAll(standaloneFilesToDelete);
        }
    }
}