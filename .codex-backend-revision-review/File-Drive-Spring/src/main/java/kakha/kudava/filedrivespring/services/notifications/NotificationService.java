package kakha.kudava.filedrivespring.services.notifications;

import jakarta.persistence.EntityNotFoundException;
import kakha.kudava.filedrivespring.enums.EntityType;
import kakha.kudava.filedrivespring.enums.NotificationType;
import kakha.kudava.filedrivespring.enums.SharingRole;
import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.model.Notification;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.NotificationRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;

@Service
@Transactional(readOnly = true)
public class NotificationService {

    private final NotificationRepository notificationRepository;

    public NotificationService(
            NotificationRepository notificationRepository
    ) {
        this.notificationRepository = notificationRepository;
    }

    @Transactional
    public Notification createNotification(
            User recipient,
            User actor,
            NotificationType type,
            String title,
            String message,
            EntityType entityType,
            Long entityId
    ) {
        Notification notification = new Notification(
                recipient,
                actor,
                type,
                title,
                message,
                entityType,
                entityId
        );

        return notificationRepository.save(notification);
    }

    @Transactional
    public Notification createNotification(
            User recipient,
            User actor,
            NotificationType type,
            String title,
            String message
    ) {
        return createNotification(
                recipient,
                actor,
                type,
                title,
                message,
                null,
                null
        );
    }

    @Transactional
    public Notification notifyUploadCompleted(
            User recipient,
            FileMetaData file
    ) {
        Notification notification = createNotification(
                recipient,
                null,
                NotificationType.UPLOAD_COMPLETED,
                "Upload complete",
                quote(file.getFileName())
                        + " was uploaded successfully.",
                EntityType.FILE,
                file.getId()
        );

        notification.setResourceDetails(
                file.getFileName(),
                file.getObjectType(),
                file.getSize(),
                buildFolderPath(file.getParent())
        );

        notification.setSecurityDetails(
                "CLEAN",
                null
        );

        return notification;
    }

    /**
     * Preferred malware helper. Pass the ClamAV response so the modal can
     * display the detected signature or scan result.
     */
    @Transactional
    public Notification notifyMalwareDetected(
            User recipient,
            String fileName,
            String threat
    ) {
        Notification notification = createNotification(
                recipient,
                null,
                NotificationType.MALWARE_DETECTED,
                "Upload blocked",
                quote(fileName)
                        + " was blocked because a security threat was detected."
        );

        notification.setResourceDetails(
                fileName,
                null,
                null,
                null
        );

        notification.setSecurityDetails(
                "BLOCKED",
                threat
        );

        return notification;
    }

    /**
     * Compatibility overload for existing callers.
     */
    @Transactional
    public Notification notifyMalwareDetected(
            User recipient,
            String fileName
    ) {
        return notifyMalwareDetected(
                recipient,
                fileName,
                null
        );
    }

    @Transactional
    public Notification notifyFileShared(
            User recipient,
            User actor,
            FileMetaData file,
            SharingRole role
    ) {
        SharingRole safeRole = normalizeRole(role);

        Notification notification = createNotification(
                recipient,
                actor,
                NotificationType.FILE_SHARED,
                "File shared with you",
                actor.getUsername()
                        + " shared "
                        + quote(file.getFileName())
                        + " with you as "
                        + roleLabel(safeRole)
                        + ".",
                EntityType.FILE,
                file.getId()
        );

        notification.setResourceDetails(
                file.getFileName(),
                file.getObjectType(),
                file.getSize(),
                buildFolderPath(file.getParent())
        );

        notification.setPermissionRole(
                safeRole.name()
        );

        return notification;
    }

    @Transactional
    public Notification notifyFolderShared(
            User recipient,
            User actor,
            Folders folder,
            SharingRole role
    ) {
        SharingRole safeRole = normalizeRole(role);

        Notification notification = createNotification(
                recipient,
                actor,
                NotificationType.FOLDER_SHARED,
                "Folder shared with you",
                actor.getUsername()
                        + " shared "
                        + quote(folder.getName())
                        + " with you as "
                        + roleLabel(safeRole)
                        + ".",
                EntityType.FOLDER,
                folder.getId()
        );

        notification.setResourceDetails(
                folder.getName(),
                "inode/directory",
                null,
                buildFolderPath(folder.getParent())
        );

        notification.setPermissionRole(
                safeRole.name()
        );

        return notification;
    }

    @Transactional
    public Notification notifyAccessRevoked(
            User recipient,
            User actor,
            EntityType entityType,
            Long entityId,
            String entityName,
            SharingRole previousRole
    ) {
        String resourceLabel =
                entityType == EntityType.FOLDER
                        ? "folder"
                        : "file";

        Notification notification = createNotification(
                recipient,
                actor,
                NotificationType.ACCESS_REVOKED,
                "Access removed",
                actor.getUsername()
                        + " removed your access to the "
                        + resourceLabel
                        + " "
                        + quote(entityName)
                        + ".",
                entityType,
                entityId
        );

        notification.setResourceDetails(
                entityName,
                entityType == EntityType.FOLDER
                        ? "inode/directory"
                        : null,
                null,
                null
        );

        if (previousRole != null) {
            notification.setPermissionRole(
                    previousRole.name()
            );
        }

        return notification;
    }

    /**
     * Compatibility overload for callers that do not yet pass the old role.
     */
    @Transactional
    public Notification notifyAccessRevoked(
            User recipient,
            User actor,
            EntityType entityType,
            Long entityId,
            String entityName
    ) {
        return notifyAccessRevoked(
                recipient,
                actor,
                entityType,
                entityId,
                entityName,
                null
        );
    }

    public Page<Notification> getNotifications(
            User recipient,
            Pageable pageable
    ) {
        return notificationRepository
                .findAllByRecipientAndRemovedAtIsNullOrderByCreatedAtDesc(
                        recipient,
                        pageable
                );
    }

    public long getUnreadCount(User recipient) {
        return notificationRepository
                .countByRecipientAndReadAtIsNullAndRemovedAtIsNull(
                        recipient
                );
    }

    @Transactional
    public Notification markRead(
            Long notificationId,
            User recipient
    ) {
        Notification notification =
                getOwnedActiveNotification(
                        notificationId,
                        recipient
                );

        notification.markRead();

        return notification;
    }

    @Transactional
    public Notification markUnread(
            Long notificationId,
            User recipient
    ) {
        Notification notification =
                getOwnedActiveNotification(
                        notificationId,
                        recipient
                );

        notification.markUnread();

        return notification;
    }

    @Transactional
    public int markAllRead(User recipient) {
        return notificationRepository.markAllReadByRecipient(
                recipient,
                Instant.now()
        );
    }

    @Transactional
    public void removeNotification(
            Long notificationId,
            User recipient
    ) {
        Notification notification =
                getOwnedActiveNotification(
                        notificationId,
                        recipient
                );

        notification.remove();
    }

    private Notification getOwnedActiveNotification(
            Long notificationId,
            User recipient
    ) {
        return notificationRepository
                .findByIdAndRecipientAndRemovedAtIsNull(
                        notificationId,
                        recipient
                )
                .orElseThrow(() ->
                        new EntityNotFoundException(
                                "Notification not found"
                        )
                );
    }

    private String buildFolderPath(Folders folder) {
        if (folder == null) {
            return "My Drive";
        }

        Deque<String> names = new ArrayDeque<>();
        Folders current = folder;

        while (current != null) {
            if (
                    current.getName() != null &&
                            !current.getName().isBlank()
            ) {
                names.addFirst(current.getName().trim());
            }

            current = current.getParent();
        }

        return names.isEmpty()
                ? "My Drive"
                : String.join(" / ", names);
    }

    private SharingRole normalizeRole(SharingRole role) {
        return role == null
                ? SharingRole.VIEWER
                : role;
    }

    private String roleLabel(SharingRole role) {
        return normalizeRole(role)
                .name()
                .toLowerCase(Locale.ROOT);
    }

    private String quote(String value) {
        String safeValue =
                value == null || value.isBlank()
                        ? "Untitled"
                        : value.trim();

        return "\"" + safeValue + "\"";
    }
}