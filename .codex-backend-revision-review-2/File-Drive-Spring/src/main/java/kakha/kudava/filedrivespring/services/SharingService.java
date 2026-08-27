package kakha.kudava.filedrivespring.services;

import kakha.kudava.filedrivespring.dto.share.ShareRequestDTO;
import kakha.kudava.filedrivespring.dto.share.SharedItemDTO;
import kakha.kudava.filedrivespring.enums.EntityType;
import kakha.kudava.filedrivespring.enums.SharingRole;
import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.model.SharingPermission;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import kakha.kudava.filedrivespring.repository.FolderRepository;
import kakha.kudava.filedrivespring.repository.SharingPermissionRepository;
import kakha.kudava.filedrivespring.repository.UserRepository;
import kakha.kudava.filedrivespring.services.notifications.NotificationService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class SharingService {

    private final SharingPermissionRepository sharingPermissionRepository;
    private final FileMetaDataRepository fileMetaDataRepository;
    private final FolderRepository folderRepository;
    private final UserRepository userRepository;
    private final LogsService logsService;
    private final NotificationService notificationService;

    public SharingService(
            SharingPermissionRepository sharingPermissionRepository,
            FileMetaDataRepository fileMetaDataRepository,
            FolderRepository folderRepository,
            UserRepository userRepository,
            LogsService logsService, NotificationService notificationService
    ) {
        this.sharingPermissionRepository = sharingPermissionRepository;
        this.fileMetaDataRepository = fileMetaDataRepository;
        this.folderRepository = folderRepository;
        this.userRepository = userRepository;
        this.logsService = logsService;
        this.notificationService = notificationService;
    }

    private record ShareResult(
            SharingPermission permission,
            boolean changed
    ) {
    }

    private User currentUser() {
        Authentication auth =
                SecurityContextHolder.getContext().getAuthentication();

        if (auth == null
                || !auth.isAuthenticated()
                || auth.getName() == null) {
            throw new RuntimeException("Not authenticated");
        }

        return userRepository.findByUsername(auth.getName())
                .orElseThrow(() ->
                        new RuntimeException(
                                "Authenticated user not found: "
                                        + auth.getName()
                        )
                );
    }

    @Transactional
    public List<SharedItemDTO> share(ShareRequestDTO request) {
        if (request == null) {
            throw new RuntimeException("Share request cannot be null");
        }

        boolean hasFiles =
                request.getFileIds() != null
                        && !request.getFileIds().isEmpty();

        boolean hasFolders =
                request.getFolderIds() != null
                        && !request.getFolderIds().isEmpty();

        if (!hasFiles && !hasFolders) {
            throw new RuntimeException("No files or folders selected");
        }

        if (request.getTargetUsername() == null
                || request.getTargetUsername().isBlank()) {
            throw new RuntimeException("Target username is required");
        }

        List<SharedItemDTO> results = new ArrayList<>();

        if (hasFiles) {
            results.addAll(
                    shareFiles(
                            request.getFileIds(),
                            request.getTargetUsername(),
                            request.getRole()
                    )
            );
        }

        if (hasFolders) {
            results.addAll(
                    shareFolders(
                            request.getFolderIds(),
                            request.getTargetUsername(),
                            request.getRole()
                    )
            );
        }

        return results;
    }

    @Transactional
    public List<SharedItemDTO> shareFiles(
            List<Long> fileIds,
            String targetUsername,
            SharingRole role
    ) {
        User owner = currentUser();

        if (fileIds == null || fileIds.isEmpty()) {
            throw new RuntimeException("No files selected");
        }

        User sharedWith = userRepository
                .findByUsername(targetUsername)
                .orElseThrow(() ->
                        new RuntimeException(
                                "User not found: " + targetUsername
                        )
                );

        validateNotSharingWithSelf(owner, sharedWith);

        SharingRole normalizedRole = normalizeRole(role);
        List<SharedItemDTO> sharedItems = new ArrayList<>();

        for (Long fileId : fileIds.stream()
                .filter(id -> id != null)
                .distinct()
                .toList()) {

            FileMetaData file = requireOwnedFile(fileId, owner);

            ShareResult result = upsertFileShare(
                    file,
                    owner,
                    sharedWith,
                    normalizedRole
            );

            SharingPermission permission = result.permission();

            if (result.changed()) {
                logsService.shareLog(
                        file.getId(),
                        EntityType.FILE,
                        permission.getId(),
                        sharedWith.getId(),
                        permission.getRole()
                );
                notificationService.notifyFileShared(
                        sharedWith,
                        owner,
                        file,
                        permission.getRole()
                );
            }

            sharedItems.add(toDto(permission));
        }

        return sharedItems;
    }

    @Transactional
    public List<SharedItemDTO> shareFolders(
            List<Long> folderIds,
            String targetUsername,
            SharingRole role
    ) {
        User owner = currentUser();

        if (folderIds == null || folderIds.isEmpty()) {
            throw new RuntimeException("No folders selected");
        }

        User sharedWith = userRepository
                .findByUsername(targetUsername)
                .orElseThrow(() ->
                        new RuntimeException(
                                "User not found: " + targetUsername
                        )
                );

        validateNotSharingWithSelf(owner, sharedWith);

        SharingRole normalizedRole = normalizeRole(role);
        List<SharedItemDTO> sharedItems = new ArrayList<>();

        for (Long folderId : folderIds.stream()
                .filter(id -> id != null)
                .distinct()
                .toList()) {

            Folders folder = requireOwnedFolder(folderId, owner);

            if (folder.getParent() == null) {
                throw new RuntimeException(
                        "Sharing the root folder is not allowed. "
                                + "Invalid folder id: "
                                + folderId
                );
            }

            ShareResult result = upsertFolderShare(
                    folder,
                    owner,
                    sharedWith,
                    normalizedRole
            );

            SharingPermission permission = result.permission();

            if (result.changed()) {
                logsService.shareLog(
                        folder.getId(),
                        EntityType.FOLDER,
                        permission.getId(),
                        sharedWith.getId(),
                        permission.getRole()
                );
                notificationService.notifyFolderShared(
                        sharedWith,
                        owner,
                        folder,
                        permission.getRole()
                );
            }

            sharedItems.add(toDto(permission));
        }

        return sharedItems;
    }

    @Transactional
    public void revokeShare(Long shareId) {
        User owner = currentUser();

        SharingPermission permission =
                sharingPermissionRepository.findById(shareId)
                        .orElseThrow(() ->
                                new RuntimeException("Share not found")
                        );

        if (!permission.isActive()) {
            throw new RuntimeException("Share not found");
        }

        User recipient = permission.getSharedWith();

        Long entityId;
        EntityType entityType;
        String entityName;

        if (permission.getFile() != null) {
            FileMetaData file = permission.getFile();

            if (!ownsFile(file, owner)) {
                throw new RuntimeException("Share not found");
            }

            entityId = file.getId();
            entityType = EntityType.FILE;
            entityName = file.getFileName();

        } else if (permission.getFolder() != null) {
            Folders folder = permission.getFolder();

            if (!ownsFolder(folder, owner)) {
                throw new RuntimeException("Share not found");
            }

            entityId = folder.getId();
            entityType = EntityType.FOLDER;
            entityName = folder.getName();

        } else {
            throw new RuntimeException("Invalid share");
        }

        permission.setActive(false);
        permission.setRevokedAt(Instant.now());
        permission.setUpdatedAt(Instant.now());

        sharingPermissionRepository.save(permission);

        logsService.shareRevokeLog(
                entityId,
                entityType,
                permission.getId(),
                recipient.getId(),
                permission.getRole()
        );

        notificationService.notifyAccessRevoked(
                recipient,
                owner,
                entityType,
                entityId,
                entityName
        );
    }
    @Transactional(readOnly = true)
    public List<SharedItemDTO> getSharedWithMe() {
        User user = currentUser();

        return sharingPermissionRepository
                .findBySharedWithAndActiveTrue(user)
                .stream()
                .map(this::toDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<SharedItemDTO> getSharedByMe() {
        User owner = currentUser();

        return sharingPermissionRepository
                .findByOwnerAndActiveTrue(owner)
                .stream()
                .map(this::toDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<SharedItemDTO> getFileShares(Long fileId) {
        User owner = currentUser();
        FileMetaData file = requireOwnedFile(fileId, owner);

        return sharingPermissionRepository
                .findByFileAndActiveTrue(file)
                .stream()
                .map(this::toDto)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<SharedItemDTO> getFolderShares(Long folderId) {
        User owner = currentUser();
        Folders folder = requireOwnedFolder(folderId, owner);

        return sharingPermissionRepository
                .findByFolderAndActiveTrue(folder)
                .stream()
                .map(this::toDto)
                .toList();
    }

    public boolean canViewFile(FileMetaData file, User user) {
        if (ownsFile(file, user)) {
            return true;
        }

        if (hasDirectFileRole(
                file,
                user,
                SharingRole.VIEWER
        )) {
            return true;
        }

        return file.getParent() != null
                && canAccessFolder(
                file.getParent(),
                user,
                SharingRole.VIEWER
        );
    }

    public boolean canEditFile(FileMetaData file, User user) {
        if (ownsFile(file, user)) {
            return true;
        }

        if (hasDirectFileRole(
                file,
                user,
                SharingRole.EDITOR
        )) {
            return true;
        }

        return file.getParent() != null
                && canAccessFolder(
                file.getParent(),
                user,
                SharingRole.EDITOR
        );
    }

    public boolean canViewFolder(Folders folder, User user) {
        return canAccessFolder(
                folder,
                user,
                SharingRole.VIEWER
        );
    }

    public boolean canEditFolder(Folders folder, User user) {
        return canAccessFolder(
                folder,
                user,
                SharingRole.EDITOR
        );
    }

    public boolean showsSharedIndicator(
            FileMetaData file,
            User viewer
    ) {
        if (file == null || viewer == null) {
            return false;
        }

        if (!ownsFile(file, viewer)) {
            return true;
        }

        if (sharingPermissionRepository
                .existsByFileAndActiveTrue(file)) {
            return true;
        }

        return file.getParent() != null
                && hasActiveFolderShareInChain(
                file.getParent()
        );
    }

    public boolean showsSharedIndicator(
            Folders folder,
            User viewer
    ) {
        if (folder == null || viewer == null) {
            return false;
        }

        if (!ownsFolder(folder, viewer)) {
            return true;
        }

        return hasActiveFolderShareInChain(folder);
    }

    private ShareResult upsertFileShare(
            FileMetaData file,
            User owner,
            User sharedWith,
            SharingRole role
    ) {
        Optional<SharingPermission> existing =
                sharingPermissionRepository
                        .findByFileAndSharedWith(
                                file,
                                sharedWith
                        );

        if (existing.isPresent()) {
            SharingPermission permission = existing.get();

            boolean changed =
                    !permission.isActive()
                            || permission.getRole() != role;

            if (!changed) {
                return new ShareResult(
                        permission,
                        false
                );
            }

            permission.setFile(file);
            permission.setFolder(null);
            permission.setOwner(owner);
            permission.setSharedBy(owner);
            permission.setSharedWith(sharedWith);
            permission.setRole(role);
            permission.setActive(true);
            permission.setRevokedAt(null);
            permission.setUpdatedAt(Instant.now());

            SharingPermission saved =
                    sharingPermissionRepository.save(permission);

            return new ShareResult(saved, true);
        }

        SharingPermission permission =
                new SharingPermission();

        permission.setFile(file);
        permission.setFolder(null);
        permission.setOwner(owner);
        permission.setSharedBy(owner);
        permission.setSharedWith(sharedWith);
        permission.setRole(role);
        permission.setActive(true);
        permission.setRevokedAt(null);
        permission.setUpdatedAt(Instant.now());

        SharingPermission saved =
                sharingPermissionRepository.save(permission);

        return new ShareResult(saved, true);
    }

    private ShareResult upsertFolderShare(
            Folders folder,
            User owner,
            User sharedWith,
            SharingRole role
    ) {
        Optional<SharingPermission> existing =
                sharingPermissionRepository
                        .findByFolderAndSharedWith(
                                folder,
                                sharedWith
                        );

        if (existing.isPresent()) {
            SharingPermission permission = existing.get();

            boolean changed =
                    !permission.isActive()
                            || permission.getRole() != role;

            if (!changed) {
                return new ShareResult(
                        permission,
                        false
                );
            }

            permission.setFolder(folder);
            permission.setFile(null);
            permission.setOwner(owner);
            permission.setSharedBy(owner);
            permission.setSharedWith(sharedWith);
            permission.setRole(role);
            permission.setActive(true);
            permission.setRevokedAt(null);
            permission.setUpdatedAt(Instant.now());

            SharingPermission saved =
                    sharingPermissionRepository.save(permission);

            return new ShareResult(saved, true);
        }

        SharingPermission permission =
                new SharingPermission();

        permission.setFolder(folder);
        permission.setFile(null);
        permission.setOwner(owner);
        permission.setSharedBy(owner);
        permission.setSharedWith(sharedWith);
        permission.setRole(role);
        permission.setActive(true);
        permission.setRevokedAt(null);
        permission.setUpdatedAt(Instant.now());

        SharingPermission saved =
                sharingPermissionRepository.save(permission);

        return new ShareResult(saved, true);
    }

    private FileMetaData requireOwnedFile(
            Long fileId,
            User owner
    ) {
        FileMetaData file =
                fileMetaDataRepository.findById(fileId)
                        .orElseThrow(() ->
                                new RuntimeException(
                                        "File not found"
                                )
                        );

        if (!ownsFile(file, owner)) {
            throw new RuntimeException("File not found");
        }

        return file;
    }

    private Folders requireOwnedFolder(
            Long folderId,
            User owner
    ) {
        Folders folder =
                folderRepository.findById(folderId)
                        .orElseThrow(() ->
                                new RuntimeException(
                                        "Folder not found"
                                )
                        );

        if (!ownsFolder(folder, owner)) {
            throw new RuntimeException("Folder not found");
        }

        return folder;
    }

    private boolean hasActiveFolderShareInChain(
            Folders folder
    ) {
        Folders current = folder;

        while (current != null) {
            if (sharingPermissionRepository
                    .existsByFolderAndActiveTrue(current)) {
                return true;
            }

            current = current.getParent();
        }

        return false;
    }

    private boolean canAccessFolder(
            Folders folder,
            User user,
            SharingRole requiredRole
    ) {
        Folders current = folder;

        while (current != null) {
            if (ownsFolder(current, user)) {
                return true;
            }

            Optional<SharingPermission> permission =
                    sharingPermissionRepository
                            .findByFolderAndSharedWithAndActiveTrue(
                                    current,
                                    user
                            );

            if (permission.isPresent()
                    && roleIncludes(
                    permission.get().getRole(),
                    requiredRole
            )) {
                return true;
            }

            current = current.getParent();
        }

        return false;
    }

    private boolean hasDirectFileRole(
            FileMetaData file,
            User user,
            SharingRole requiredRole
    ) {
        return sharingPermissionRepository
                .findByFileAndSharedWithAndActiveTrue(
                        file,
                        user
                )
                .map(permission ->
                        roleIncludes(
                                permission.getRole(),
                                requiredRole
                        )
                )
                .orElse(false);
    }

    private boolean ownsFile(
            FileMetaData file,
            User user
    ) {
        return file != null
                && file.getOwner() != null
                && sameUser(file.getOwner(), user);
    }

    private boolean ownsFolder(
            Folders folder,
            User user
    ) {
        return folder != null
                && folder.getOwner() != null
                && sameUser(folder.getOwner(), user);
    }

    private boolean sameUser(User a, User b) {
        return a != null
                && b != null
                && a.getId() != null
                && a.getId().equals(b.getId());
    }

    private void validateNotSharingWithSelf(
            User owner,
            User sharedWith
    ) {
        if (sameUser(owner, sharedWith)) {
            throw new RuntimeException(
                    "You cannot share a resource with yourself"
            );
        }
    }

    private SharingRole normalizeRole(SharingRole role) {
        return role == null
                ? SharingRole.VIEWER
                : role;
    }

    private boolean roleIncludes(
            SharingRole actualRole,
            SharingRole requiredRole
    ) {
        if (actualRole == SharingRole.EDITOR) {
            return true;
        }

        return actualRole == SharingRole.VIEWER
                && requiredRole == SharingRole.VIEWER;
    }

    private SharedItemDTO toDto(
            SharingPermission permission
    ) {
        SharedItemDTO dto = new SharedItemDTO();

        dto.setShareId(permission.getId());
        dto.setOwnerUsername(
                permission.getOwner().getUsername()
        );
        dto.setSharedWithUsername(
                permission.getSharedWith().getUsername()
        );
        dto.setRole(permission.getRole());

        if (permission.getFile() != null) {
            dto.setResourceType("FILE");
            dto.setResourceId(
                    permission.getFile().getId()
            );
            dto.setName(
                    permission.getFile().getFileName()
            );
            dto.setSize(
                    permission.getFile().getSize()
            );

        } else if (permission.getFolder() != null) {
            dto.setResourceType("FOLDER");
            dto.setResourceId(
                    permission.getFolder().getId()
            );
            dto.setName(
                    permission.getFolder().getName()
            );
            dto.setSize(null);
        }

        return dto;
    }
}