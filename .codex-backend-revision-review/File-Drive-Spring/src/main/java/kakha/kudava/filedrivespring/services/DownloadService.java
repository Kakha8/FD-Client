package kakha.kudava.filedrivespring.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import kakha.kudava.filedrivespring.dto.DownloadZipRequest;

import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.records.ZipCount;
import kakha.kudava.filedrivespring.records.ZipDownloadResult;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import kakha.kudava.filedrivespring.repository.FolderRepository;
import kakha.kudava.filedrivespring.services.objects.ObjectStorageService;
import lombok.extern.slf4j.Slf4j;
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
public class DownloadService {

    private final FileMetaDataRepository fileMetaDataRepository;
    private final FolderRepository folderRepository;
    private final ObjectStorageService objectStorageService;
    private final LogsService logsService;
    private final ObjectMapper objectMapper;
    private final ResourceAccessService access;
    private final SharingService sharingService;

    public DownloadService(
            FileMetaDataRepository fileMetaDataRepository,
            FolderRepository folderRepository,
            ObjectStorageService objectStorageService, LogsService logsService, ObjectMapper objectMapper, ResourceAccessService access, SharingService sharingService
    ) {
        this.fileMetaDataRepository = fileMetaDataRepository;
        this.folderRepository = folderRepository;
        this.objectStorageService = objectStorageService;
        this.logsService = logsService;
        this.objectMapper = objectMapper;
        this.access = access;
        this.sharingService = sharingService;
    }

    public ZipDownloadResult downloadAsZip(DownloadZipRequest request) throws Exception {
        List<Long> fileIds = request.getFileIds() == null ? List.of() : request.getFileIds();
        List<Long> folderIds = request.getFolderIds() == null ? List.of() : request.getFolderIds();

        if (fileIds.isEmpty() && folderIds.isEmpty()) {
            throw new RuntimeException("No items selected");
        }

        // Resolve top-level resources and the user on the request thread. The
        // StreamingResponseBody itself runs asynchronously, where the security
        // context is not guaranteed to be available.
        List<FileMetaData> files = fileIds.stream()
                .map(access::requireFileView)
                .toList();
        List<Folders> folders = folderIds.stream()
                .map(access::requireFolderView)
                .toList();
        User user = access.currentUser();

        return new ZipDownloadResult(
                "download.zip",
                outputStream -> writeZip(files, folders, fileIds, folderIds, user, outputStream)
        );
    }

    private void writeZip(
            List<FileMetaData> files,
            List<Folders> folders,
            List<Long> selectedFileIds,
            List<Long> selectedFolderIds,
            User user,
            OutputStream outputStream
    ) throws IOException {
        CountingOutputStream countingOutputStream = new CountingOutputStream(outputStream);
        Set<String> usedZipNames = new HashSet<>();
        int fileCount = 0;
        int folderCount = 0;

        try {
            try (ZipOutputStream zipOutputStream = new ZipOutputStream(countingOutputStream)) {

                for (FileMetaData file : files) {
                    addFileToZip(file, "", zipOutputStream, usedZipNames);
                    fileCount++;
                }

                for (Folders folder : folders) {
                    String folderPath = uniqueZipName(
                            sanitizeZipName(folder.getName()) + "/",
                            usedZipNames
                    );
                    ZipCount count = addFolderToZip(folder, folderPath, zipOutputStream, usedZipNames, user);
                    fileCount += count.fileCount();
                    folderCount += count.folderCount();
                }
            }

            Map<String, Object> details = new LinkedHashMap<>();
            details.put("downloadName", "download.zip");
            details.put("selectedFileIds", selectedFileIds);
            details.put("selectedFolderIds", selectedFolderIds);
            details.put("fileCount", fileCount);
            details.put("folderCount", folderCount);
            details.put("zipSizeBytes", countingOutputStream.getByteCount());
            try {
                logsService.bulkDownloadLog(objectMapper.writeValueAsString(details));
            } catch (Exception e) {
                log.error("ZIP was streamed, but bulk-download logging failed", e);
            }
        } catch (Exception e) {
            if (e instanceof IOException ioException) {
                throw ioException;
            }
            throw new IOException("Failed to stream ZIP download", e);
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
}
