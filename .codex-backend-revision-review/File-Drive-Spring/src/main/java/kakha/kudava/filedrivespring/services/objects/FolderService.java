package kakha.kudava.filedrivespring.services.objects;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.minio.MinioClient;
import jakarta.transaction.Transactional;
import kakha.kudava.filedrivespring.dto.*;
import kakha.kudava.filedrivespring.enums.DriveSpace;
import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.records.FolderDownloadResult;
import kakha.kudava.filedrivespring.records.ZipCount;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import kakha.kudava.filedrivespring.repository.FolderRepository;
import kakha.kudava.filedrivespring.repository.UserRepository;
import kakha.kudava.filedrivespring.services.LogsService;
import kakha.kudava.filedrivespring.services.ResourceAccessService;
import kakha.kudava.filedrivespring.services.SharingService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@Slf4j
@Service
public class FolderService {

    private final FolderRepository folderRepository;
    private final ObjectStorageService objectStorageService;
    private final UserRepository userRepository;
    private final RootFolderService rootFolderService;
    private final ResourceAccessService access;

    @Value("${s3.bucket}")
    private String bucket;
    private final MinioClient minioClient;
    private final FileMetaDataRepository fileMetaDataRepository;
    private final ObjectMapper objectMapper;
    private final LogsService logsService;
    private final SharingService sharingService;
    public FolderService(FolderRepository folderRepository, ObjectStorageService objectStorageService, UserRepository userRepository, RootFolderService rootFolderService, ResourceAccessService access,
                         MinioClient minioClient,
                         FileMetaDataRepository fileMetaDataRepository, ObjectMapper objectMapper, LogsService logsService, SharingService sharingService) {
        this.folderRepository = folderRepository;
        this.objectStorageService = objectStorageService;
        this.userRepository = userRepository;
        this.rootFolderService = rootFolderService;
        this.access = access;
        this.minioClient = minioClient;
        this.fileMetaDataRepository = fileMetaDataRepository;
        this.objectMapper = objectMapper;
        this.logsService = logsService;
        this.sharingService = sharingService;
    }

    private User currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || auth.getName() == null) {
            throw new RuntimeException("Not authenticated");
        }

        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new RuntimeException("Authenticated user not found: " + auth.getName()));
    }

    @Transactional
    public FolderDTO create(FolderCreateRequest req) throws Exception {
        User user = access.currentUser();

        if (req == null || req.getName() == null || req.getName().isBlank()) {
            throw new IllegalArgumentException("Folder name is required");
        }

        Folders parent;

        if (req.getParentId() == null) {
            parent = requireDriveFolder(
                    rootFolderService.ensureRootFolder(user)
            );
        } else {
            parent = requireDriveFolder(
                    access.requireFolderEdit(req.getParentId())
            );
        }

        String cleanName = req.getName()
                .trim()
                .replace("\\", "/")
                .replaceAll("^/|/$", "");

        if (cleanName.isBlank()) {
            throw new IllegalArgumentException("Folder name is required");
        }

        if (cleanName.contains("/")) {
            throw new IllegalArgumentException("Folder name cannot contain slashes");
        }

        String parentPrefix = parent.getPrefix();

        if (parentPrefix == null || parentPrefix.isBlank()) {
            throw new RuntimeException("Parent folder prefix is missing");
        }

        if (!parentPrefix.endsWith("/")) {
            parentPrefix += "/";
        }

        String fullPrefix = parentPrefix + cleanName + "/";

        folderRepository
                .findByPrefixAndOwnerAndDriveSpaceAndDeletedFalseAndPermanentlyDeletedFalse(
                        fullPrefix,
                        parent.getOwner(),
                        DriveSpace.DRIVE
                )
                .ifPresent(existing -> {
                    throw new RuntimeException("Folder already exists: " + cleanName);
                });

        Folders entity = new Folders();
        entity.setName(cleanName);
        entity.setPrefix(fullPrefix);
        entity.setParent(parent);

        /*
         * Folder owner owns the whole tree.
         * Editors are contributors, not owners.
         */
        entity.setOwner(parent.getOwner());
        entity.setDriveSpace(parent.getDriveSpace());

        entity.setDeleted(false);
        entity.setPermanentlyDeleted(false);

        Folders saved = folderRepository.save(entity);

        return toDto(saved);
    }

    private String buildFullPrefix(String folderName, Long parentId) {
        String normalizedName = folderName.replaceAll("^/|/$", "");

        if (parentId == null) {
            User user = access.currentUser();
            Folders root = requireDriveFolder(
                    rootFolderService.ensureRootFolder(user)
            );

            String rootPrefix = root.getPrefix();
            if (!rootPrefix.endsWith("/")) {
                rootPrefix += "/";
            }

            return rootPrefix + normalizedName + "/";
        }

        Folders parent = requireDriveFolder(
                access.requireFolderEdit(parentId)
        );

        String parentPrefix = parent.getPrefix();
        if (!parentPrefix.endsWith("/")) {
            parentPrefix += "/";
        }

        return parentPrefix + normalizedName + "/";
    }

    @Transactional
    public void delete(Long id) throws Exception {
        Folders folder = requireDriveFolder(
                access.requireFolderOwner(id)
        );

        if (folder.getParent() == null) {
            throw new RuntimeException("Root folder cannot be deleted");
        }

        String prefix = folder.getPrefix();

        if (prefix == null || prefix.isBlank()) {
            throw new RuntimeException("Folder prefix is missing");
        }

        String normalizedPrefix = prefix.trim().replace("\\", "/");

        if (!normalizedPrefix.endsWith("/")) {
            normalizedPrefix += "/";
        }

        objectStorageService.deleteByPrefix(normalizedPrefix);

        int filesDeleted = fileMetaDataRepository.softDeleteFilesByFolderPrefix(normalizedPrefix);
        int foldersDeleted = folderRepository.softDeleteTreeByPrefix(normalizedPrefix);

        log.info(
                "Soft-deleted {} files and {} folders for prefix={}",
                filesDeleted,
                foldersDeleted,
                normalizedPrefix
        );

        logsService.deleteLog(
                folder.getName(),
                folder.getId(),
                "FOLDER"
        );
    }

    public List<FolderItemDTO> viewFolders(Long id) {
        Folders parent = requireDriveFolder(
                access.requireFolderView(id)
        );
        User user = access.currentUser();

        List<Folders> folders =
                folderRepository.findFoldersByParent_Id(parent.getId())
                        .stream()
                        .filter(folder -> folder.getDriveSpace() == DriveSpace.DRIVE)
                        .filter(folder -> !folder.isDeleted())
                        .filter(folder -> !folder.isPermanentlyDeleted())
                        .filter(folder -> sharingService.canViewFolder(folder, user))
                        .toList();

        return folders.stream().map(f -> {
            FolderItemDTO dto = new FolderItemDTO();
            dto.setId(f.getId());
            dto.setName(f.getName());
            dto.setPrefix(f.getPrefix());
            dto.setShared(sharingService.showsSharedIndicator(f, user));
            dto.setOwnerUsername(f.getOwner() == null ? null : f.getOwner().getUsername());
            return dto;
        }).toList();
    }

    public List<FileItemDTO> viewFiles(Long id) {
        Folders folder = requireDriveFolder(
                access.requireFolderView(id)
        );
        User user = access.currentUser();

        List<FileMetaData> files =
                fileMetaDataRepository.findByParent_IdAndDeletedFalse(folder.getId())
                        .stream()
                        .filter(file -> file.getDriveSpace() == DriveSpace.DRIVE)
                        .filter(file -> !file.isPermanentlyDeleted())
                        .filter(file -> sharingService.canViewFile(file, user))
                        .toList();
        return files.stream().map(file -> {
            FileItemDTO dto = new FileItemDTO();
            dto.setId(file.getId());
            dto.setFileName(file.getFileName());
            dto.setObjectType(file.getObjectType());
            dto.setSize(file.getSize());
            dto.setDeleted(file.isDeleted());
            dto.setParentId(file.getParent() != null ? file.getParent().getId() : null);
            dto.setShared(sharingService.showsSharedIndicator(file, user));
            dto.setOwnerUsername(file.getOwner() == null ? null : file.getOwner().getUsername());
            return dto;
        }).toList();
    }
    private FolderDTO toDto(Folders f) {
        FolderDTO dto = new FolderDTO();
        dto.setId(f.getId());
        dto.setName(f.getName());
        dto.setPrefix(f.getPrefix());
        dto.setParentId(f.getParent() != null ? f.getParent().getId() : null);
        return dto;
    }

    public FolderViewDTO viewCurrentUserRoot() throws Exception {
        User user = access.currentUser();

        Folders root = requireDriveFolder(
                rootFolderService.ensureRootFolder(user)
        );

        return viewFolder(root.getId());
    }

    public FolderViewDTO viewFolder(Long id) {
        User user = currentUser();

        Folders folder = requireDriveFolder(
                access.requireFolderView(id)
        );

        FolderViewDTO dto = new FolderViewDTO();
        dto.setId(folder.getId());
        dto.setName(folder.getName());
        dto.setOwnerUsername(folder.getOwner() == null ? null : folder.getOwner().getUsername());
        dto.setFolders(viewFolders(id));
        dto.setFiles(viewFiles(id));

        return dto;
    }

    public FolderDownloadResult downloadFolderAsZip(Long folderId) throws Exception {
        Folders rootFolder = requireDriveFolder(
                access.requireFolderView(folderId)
        );
        String zipName = sanitizeZipName(rootFolder.getName()) + ".zip";
        User user = access.currentUser();

        return new FolderDownloadResult(
                zipName,
                outputStream -> writeFolderZip(rootFolder, zipName, user, outputStream)
        );
    }

    private void writeFolderZip(
            Folders rootFolder,
            String zipName,
            User user,
            OutputStream outputStream
    ) throws IOException {
        CountingOutputStream countingOutputStream = new CountingOutputStream(outputStream);
        Set<String> usedZipNames = new HashSet<>();

        try {
            ZipCount count;
            try (ZipOutputStream zipOutputStream = new ZipOutputStream(countingOutputStream)) {
                String rootPath = uniqueZipName(
                        sanitizeZipName(rootFolder.getName()) + "/",
                        usedZipNames
                );
                count = addFolderToZip(
                        rootFolder,
                        rootPath,
                        zipOutputStream,
                        usedZipNames,
                        user
                );
            }

            Map<String, Object> details = new LinkedHashMap<>();
            details.put("downloadName", zipName);
            details.put("folderId", rootFolder.getId());
            details.put("folderName", rootFolder.getName());
            details.put("fileCount", count.fileCount());
            details.put("folderCount", count.folderCount());
            details.put("zipSizeBytes", countingOutputStream.getByteCount());

            try {
                logsService.folderDownloadLog(
                        objectMapper.writeValueAsString(details),
                        rootFolder.getId()
                );
            } catch (Exception e) {
                log.error("Folder ZIP was streamed, but logging failed: folderId={}", rootFolder.getId(), e);
            }
        } catch (Exception e) {
            if (e instanceof IOException ioException) {
                throw ioException;
            }
            throw new IOException("Failed to stream folder ZIP download", e);
        }
    }

    private String uniqueZipName(String desiredName, Set<String> usedZipNames) {
        if (!usedZipNames.contains(desiredName)) {
            usedZipNames.add(desiredName);
            return desiredName;
        }

        boolean isDirectory = desiredName.endsWith("/");
        String cleanName = isDirectory
                ? desiredName.substring(0, desiredName.length() - 1)
                : desiredName;

        String parentPath = "";
        String baseName = cleanName;
        String extension = "";

        int slashIndex = cleanName.lastIndexOf("/");
        if (slashIndex >= 0) {
            parentPath = cleanName.substring(0, slashIndex + 1);
            baseName = cleanName.substring(slashIndex + 1);
        }

        if (!isDirectory) {
            int dotIndex = baseName.lastIndexOf(".");
            if (dotIndex > 0) {
                extension = baseName.substring(dotIndex);
                baseName = baseName.substring(0, dotIndex);
            }
        }

        int counter = 1;

        while (true) {
            String candidate = parentPath + baseName + " (" + counter + ")" + extension;

            if (isDirectory) {
                candidate += "/";
            }

            if (!usedZipNames.contains(candidate)) {
                usedZipNames.add(candidate);
                return candidate;
            }

            counter++;
        }
    }

    private ZipCount addFolderToZip(
            Folders folder,
            String currentPath,
            ZipOutputStream zipOutputStream,
            Set<String> usedZipNames,
            User user
    ) throws Exception {
        int fileCount = 0;
        int folderCount = 1;

        addDirectoryEntry(currentPath, zipOutputStream, usedZipNames);

        List<FileMetaData> files = fileMetaDataRepository.findByParentId(folder.getId())
                .stream()
                .filter(file -> file.getDriveSpace() == DriveSpace.DRIVE)
                .filter(file -> !file.isDeleted())
                .filter(file -> !file.isPermanentlyDeleted())
                .filter(file -> sharingService.canViewFile(file, user))
                .toList();

        for (FileMetaData file : files) {
            addFileToZip(file, currentPath, zipOutputStream, usedZipNames);
            fileCount++;
        }

        List<Folders> childFolders = folderRepository.findByParentId(folder.getId())
                .stream()
                .filter(child -> child.getDriveSpace() == DriveSpace.DRIVE)
                .filter(child -> !child.isDeleted())
                .filter(child -> !child.isPermanentlyDeleted())
                .filter(child -> sharingService.canViewFolder(child, user))
                .toList();

        for (Folders childFolder : childFolders) {
            String childPath = uniqueZipName(
                    currentPath + sanitizeZipName(childFolder.getName()) + "/",
                    usedZipNames
            );

            ZipCount childCount = addFolderToZip(
                    childFolder,
                    childPath,
                    zipOutputStream,
                    usedZipNames,
                    user
            );

            fileCount += childCount.fileCount();
            folderCount += childCount.folderCount();
        }

        return new ZipCount(fileCount, folderCount);
    }

    private void addFileToZip(
            FileMetaData file,
            String folderPath,
            ZipOutputStream zipOutputStream,
            Set<String> usedZipNames
    ) throws Exception {
        String safeFileName = sanitizeZipName(file.getFileName());
        String zipPath = uniqueZipName(folderPath + safeFileName, usedZipNames);

        try (InputStream fileInputStream = objectStorageService.downloadWithoutLog(file)) {
            ZipEntry fileEntry = new ZipEntry(zipPath);
            zipOutputStream.putNextEntry(fileEntry);

            fileInputStream.transferTo(zipOutputStream);

            zipOutputStream.closeEntry();
        }
    }

    private void addDirectoryEntry(
            String folderPath,
            ZipOutputStream zipOutputStream,
            Set<String> usedZipNames
    ) throws Exception {
        String path = folderPath.endsWith("/") ? folderPath : folderPath + "/";

        ZipEntry folderEntry = new ZipEntry(path);
        zipOutputStream.putNextEntry(folderEntry);
        zipOutputStream.closeEntry();
    }

    private String sanitizeZipName(String name) {
        if (name == null || name.isBlank()) {
            return "untitled";
        }

        return name
                .replace("\\", "_")
                .replace("/", "_")
                .replace(":", "_")
                .replace("*", "_")
                .replace("?", "_")
                .replace("\"", "_")
                .replace("<", "_")
                .replace(">", "_")
                .replace("|", "_")
                .trim();
    }

    /**
     * This service handles only normal Drive folders.
     *
     * Lockbox folders use separate storage and service behavior, so they
     * must never reach normal delete, download, ZIP, or folder-creation paths.
     */
    private Folders requireDriveFolder(Folders folder) {
        Objects.requireNonNull(folder, "folder");

        if (folder.getDriveSpace() != DriveSpace.DRIVE) {
            throw new IllegalArgumentException(
                    "This operation is only available for normal Drive folders."
            );
        }

        return folder;
    }

    private static final class CountingOutputStream extends FilterOutputStream {
        private long byteCount;

        private CountingOutputStream(OutputStream outputStream) {
            super(outputStream);
        }

        @Override
        public void write(int value) throws IOException {
            out.write(value);
            byteCount++;
        }

        @Override
        public void write(byte[] bytes, int offset, int length) throws IOException {
            out.write(bytes, offset, length);
            byteCount += length;
        }

        @Override
        public void close() throws IOException {
            flush();
        }

        private long getByteCount() {
            return byteCount;
        }
    }

    @Transactional
    public void deleteMultiple(List<Long> folderIds) throws Exception {
        if (folderIds == null || folderIds.isEmpty()) {
            throw new IllegalArgumentException("No folder IDs provided");
        }

        List<Long> uniqueIds = folderIds.stream()
                .filter(Objects::nonNull)
                .distinct()
                .toList();

        if (uniqueIds.isEmpty()) {
            throw new IllegalArgumentException("No valid folder IDs provided");
        }

        for (Long folderId : uniqueIds) {
            delete(folderId);
        }
    }
}
