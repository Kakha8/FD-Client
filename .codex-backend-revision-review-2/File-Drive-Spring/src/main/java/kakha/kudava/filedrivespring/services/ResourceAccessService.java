package kakha.kudava.filedrivespring.services;

import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import kakha.kudava.filedrivespring.repository.FolderRepository;
import kakha.kudava.filedrivespring.repository.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class ResourceAccessService {

    private final FileMetaDataRepository fileRepository;
    private final FolderRepository folderRepository;
    private final UserRepository userRepository;
    private final SharingService sharingService;

    public ResourceAccessService(
            FileMetaDataRepository fileRepository,
            FolderRepository folderRepository,
            UserRepository userRepository,
            SharingService sharingService
    ) {
        this.fileRepository = fileRepository;
        this.folderRepository = folderRepository;
        this.userRepository = userRepository;
        this.sharingService = sharingService;
    }

    public User currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || auth.getName() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Not authenticated");
        }

        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED,
                        "Authenticated user not found"
                ));
    }

    public FileMetaData requireFileView(Long fileId) {
        User user = currentUser();

        FileMetaData file = fileRepository.findById(fileId)
                .orElseThrow(() -> notFound());

        if (file.isDeleted() || file.isPermanentlyDeleted()) {
            throw notFound();
        }

        if (!sharingService.canViewFile(file, user)) {
            throw notFound();
        }

        return file;
    }

    public FileMetaData requireFileEdit(Long fileId) {
        User user = currentUser();

        FileMetaData file = fileRepository.findById(fileId)
                .orElseThrow(() -> notFound());

        if (file.isDeleted() || file.isPermanentlyDeleted()) {
            throw notFound();
        }

        if (!sharingService.canEditFile(file, user)) {
            throw notFound();
        }

        return file;
    }

    public Folders requireFolderView(Long folderId) {
        User user = currentUser();

        Folders folder = folderRepository.findById(folderId)
                .orElseThrow(() -> notFound());

        if (folder.isDeleted() || folder.isPermanentlyDeleted()) {
            throw notFound();
        }

        if (!sharingService.canViewFolder(folder, user)) {
            throw notFound();
        }

        return folder;
    }

    public Folders requireFolderEdit(Long folderId) {
        User user = currentUser();

        Folders folder = folderRepository.findById(folderId)
                .orElseThrow(() -> notFound());

        if (folder.isDeleted() || folder.isPermanentlyDeleted()) {
            throw notFound();
        }

        if (!sharingService.canEditFolder(folder, user)) {
            throw notFound();
        }

        return folder;
    }

    private ResponseStatusException notFound() {
        return new ResponseStatusException(HttpStatus.NOT_FOUND, "Resource not found");
    }

    public FileMetaData requireFileOwner(Long fileId) {
        User user = currentUser();

        FileMetaData file = fileRepository.findById(fileId)
                .orElseThrow(() -> notFound());

        if (file.isDeleted() || file.isPermanentlyDeleted()) {
            throw notFound();
        }

        if (file.getOwner() == null || !file.getOwner().getId().equals(user.getId())) {
            throw notFound();
        }

        return file;
    }

    public Folders requireFolderOwner(Long folderId) {
        User user = currentUser();

        Folders folder = folderRepository.findById(folderId)
                .orElseThrow(() -> notFound());

        if (folder.isDeleted() || folder.isPermanentlyDeleted()) {
            throw notFound();
        }

        if (folder.getOwner() == null || !folder.getOwner().getId().equals(user.getId())) {
            throw notFound();
        }

        return folder;
    }


}
