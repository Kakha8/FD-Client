package kakha.kudava.filedrivespring.services.objects;

import kakha.kudava.filedrivespring.dto.FileMetaDataDTO;
import kakha.kudava.filedrivespring.exceptions.UploadCanceledException;
import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import kakha.kudava.filedrivespring.services.UploadCancellationService;
import kakha.kudava.filedrivespring.services.ResourceAccessService;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;


@Service
public class FileService {

    private final ObjectStorageService objectStorageService;
    private final FileMetaDataRepository fileMetaDataRepository;
    private final UploadCancellationService uploadCancellationService;
    private final ResourceAccessService access;

    public FileService(ObjectStorageService objectStorageService, FileMetaDataRepository fileMetaDataRepository, UploadCancellationService uploadCancellationService, ResourceAccessService access) {
        this.objectStorageService = objectStorageService;
        this.fileMetaDataRepository = fileMetaDataRepository;
        this.uploadCancellationService = uploadCancellationService;
        this.access = access;
    }

    public java.util.List<kakha.kudava.filedrivespring.dto.FileItemDTO> recent(int limit) {
        int safeLimit = Math.max(1, Math.min(limit, 100));
        return fileMetaDataRepository.findRecentFiles(access.currentUser(), PageRequest.of(0, safeLimit))
                .stream()
                .map(this::mapToItemDto)
                .toList();
    }

    private kakha.kudava.filedrivespring.dto.FileItemDTO mapToItemDto(FileMetaData file) {
        kakha.kudava.filedrivespring.dto.FileItemDTO dto = new kakha.kudava.filedrivespring.dto.FileItemDTO();
        dto.setId(file.getId());
        dto.setFileName(file.getFileName());
        dto.setObjectType(file.getObjectType());
        dto.setParentId(file.getParent() == null ? null : file.getParent().getId());
        dto.setSize(file.getSize());
        dto.setCreationDate(file.getCreationDate());
        dto.setLastModifiedDate(file.getLastModifiedDate() == null ? file.getCreationDate() : file.getLastModifiedDate());
        dto.setOwnerUsername(file.getOwner() == null ? null : file.getOwner().getUsername());
        return dto;
    }

    public FileMetaDataDTO upload(MultipartFile file, Long parentId, String uploadId) throws Exception {
        try {
            throwIfUploadCanceled(uploadId);

            FileMetaData entity = objectStorageService.upload(file, parentId, uploadId);

            throwIfUploadCanceled(uploadId);

            return mapToDto(entity);
        } finally {
            uploadCancellationService.clear(uploadId);
        }
    }

    private FileMetaDataDTO mapToDto(FileMetaData f) {
        FileMetaDataDTO dto = new FileMetaDataDTO();
        dto.setId(f.getId());
        dto.setObjectKey(f.getObjectKey());
        dto.setObjectType(f.getObjectType());
        dto.setDeleted(f.isDeleted());
        dto.setParentId(f.getParent() != null ? f.getParent().getId() : null);
        return dto;
    }

    private void throwIfUploadCanceled(String uploadId) {
        if (uploadCancellationService.isCanceled(uploadId)) {
            throw new UploadCanceledException("Upload canceled");
        }
    }
}
