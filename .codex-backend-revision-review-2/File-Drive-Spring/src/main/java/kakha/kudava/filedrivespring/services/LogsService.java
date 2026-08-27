package kakha.kudava.filedrivespring.services;

import kakha.kudava.filedrivespring.enums.ActionType;
import kakha.kudava.filedrivespring.enums.EntityType;
import kakha.kudava.filedrivespring.enums.SharingRole;
import kakha.kudava.filedrivespring.model.ActionLogs;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.ActionLogsRepository;
import kakha.kudava.filedrivespring.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
public class LogsService {

    private final ActionLogsRepository actionLogsRepository;
    private final UserRepository userRepository;
    public LogsService(ActionLogsRepository actionLogsRepository, UserRepository userRepository) {
        this.actionLogsRepository = actionLogsRepository;
        this.userRepository = userRepository;
    }

    private ActionLogs logAction(String actionType,
                                 Long entityId, String entityType,
                                 String detailsJson) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Optional<User> user = userRepository.findByUsername(auth.getName());

        ActionLogs actionLogs = new ActionLogs();
        actionLogs.setAction(ActionType.valueOf(actionType));
        actionLogs.setDetails(null);
        actionLogs.setEntityId(entityId);
        actionLogs.setUser(user.get());
        actionLogs.setEntityType(EntityType.valueOf(entityType));
        actionLogs.setDetails(detailsJson);
        return actionLogs;
    }
    public void uploadLog(String fileName, Long parentId, String entityType, String detailsJson) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        Optional<User> user = userRepository.findByUsername(auth.getName());

        ActionLogs actionLogs = new ActionLogs();
        actionLogs.setAction(ActionType.valueOf("UPLOAD"));
        actionLogs.setDetails(null);
        actionLogs.setEntityId(parentId);
        actionLogs.setUser(user.get());
        actionLogs.setEntityType(EntityType.valueOf(entityType));
        actionLogs.setDetails(detailsJson);
        actionLogsRepository.save(actionLogs);
        log.info(String.format("Logging the upload of %s to %s", fileName, parentId));

    }

    public void downloadLog(String fileName, Long parentId, String entityType){

        ActionLogs actionLogs = logAction(ActionType.DOWNLOAD.name(), parentId,
                entityType, null);
        actionLogsRepository.save(actionLogs);
        log.info(String.format("Logging the download of %s from %s", fileName, parentId));
    }

    public void deleteLog(String fileName, Long parentId, String entityType){
        ActionLogs actionLogs = logAction(ActionType.DELETE.name(), parentId,
                entityType, null);
        actionLogsRepository.save(actionLogs);
        log.info(String.format("Logging the delete of %s", fileName));
    }

    public void renameLog(String fileName, Long parentId,
                          String entityType, String detailsJson){
        ActionLogs actionLogs = logAction(ActionType.RENAME.name(), parentId,
                entityType, detailsJson);
        actionLogsRepository.save(actionLogs);
        log.info(String.format("Logging the rename of %s", fileName));
    }

    public void moveLog(String name, Long entityId, String entityType, String detailsJson){
        ActionLogs actionLogs = logAction(ActionType.MOVE.name(), entityId, entityType, detailsJson);
        actionLogsRepository.save(actionLogs);
        log.info(String.format("Logging the move of %s", name));
    }

    public void copyLog(String name, Long entityId, String entityType, String detailsJson){
        ActionLogs actionLogs = logAction(ActionType.COPY.name(), entityId, entityType, detailsJson);
        actionLogsRepository.save(actionLogs);
        log.info(String.format("Logging the move of %s", name));
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void malwareUploadLog(String name, Long parentId, String entityType, String detailsJson) {
        ActionLogs actionLogs = logAction(
                ActionType.MALWARE_UPLOAD.name(),
                parentId,
                entityType,
                detailsJson
        );

        actionLogsRepository.saveAndFlush(actionLogs);
        log.warn("Logging the malware upload of {}", name);
    }

    public void malwareDeleteLog(String name, Long parentId, String entityType) {
        ActionLogs actionLogs = logAction(ActionType.MALWARE_DELETE.name(), parentId, entityType, null);
        actionLogsRepository.save(actionLogs);
        log.info(String.format("Logging the malware delete of {}", name));
    }

    public void malwareScheduleLog(String name, Long parentId, String entityType) {

        ActionLogs actionLogs = new ActionLogs();
        actionLogs.setAction(ActionType.valueOf(ActionType.MALWARE_SCHEDULED_DELETION.name()));
        actionLogs.setDetails(null);
        actionLogs.setEntityId(null);
        actionLogs.setUser(null);
        actionLogs.setEntityType(EntityType.valueOf(entityType));
        actionLogs.setDetails(null);
        log.info(String.format("Logging the scheduled deletion of malware {} from quarantine", name));
        actionLogsRepository.save(actionLogs);
    }

    public void bulkDownloadLog(String detailsJson) {
        ActionLogs actionLogs = logAction(
                ActionType.DOWNLOAD.name(),
                null,
                EntityType.BULK.name(),
                detailsJson
        );

        actionLogsRepository.save(actionLogs);
        log.info("Logging bulk download: {}", detailsJson);
    }

    public void folderDownloadLog(String detailsJson, Long folderId) {
        ActionLogs actionLogs = logAction(
                ActionType.DOWNLOAD.name(),
                folderId,
                EntityType.FOLDER.name(),
                detailsJson
        );

        actionLogsRepository.save(actionLogs);
        log.info("Logging folder download: folderId={}, details={}", folderId, detailsJson);
    }

    public void moveToTrashLog(String name, Long entityId, String entityType, String detailsJson) {
        ActionLogs actionLogs = logAction(
                ActionType.MOVE_TO_TRASH.name(),
                entityId,
                entityType,
                detailsJson
        );

        actionLogsRepository.save(actionLogs);
        log.info("Logging move to trash: name={}, entityId={}, entityType={}", name, entityId, entityType);
    }

    public void restoreFromTrashLog(String name, Long entityId, String entityType, String detailsJson) {
        ActionLogs actionLogs = logAction(
                ActionType.RESTORE_FROM_TRASH.name(),
                entityId,
                entityType,
                detailsJson
        );

        actionLogsRepository.save(actionLogs);
        log.info("Logging restore from trash: name={}, entityId={}, entityType={}", name, entityId, entityType);
    }

    public void permanentDeleteLog(String name, Long entityId, String entityType, String detailsJson) {
        ActionLogs actionLogs = logAction(
                ActionType.PERMANENT_DELETE.name(),
                entityId,
                entityType,
                detailsJson
        );

        actionLogsRepository.save(actionLogs);
        log.info("Logging permanent delete: name={}, entityId={}, entityType={}", name, entityId, entityType);
    }

    public void clearTrashLog(String detailsJson) {
        ActionLogs actionLogs = logAction(
                ActionType.CLEAR_TRASH.name(),
                null,
                EntityType.BULK.name(),
                detailsJson
        );

        actionLogsRepository.save(actionLogs);
        log.info("Logging clear trash: {}", detailsJson);
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void trashAutoDeleteLog(User owner, Long entityId, String entityType, String detailsJson) {
        ActionLogs actionLogs = new ActionLogs();

        actionLogs.setAction(ActionType.TRASH_AUTO_DELETE);
        actionLogs.setEntityId(entityId);
        actionLogs.setEntityType(EntityType.valueOf(entityType));
        actionLogs.setUser(owner);
        actionLogs.setDetails(detailsJson);

        actionLogsRepository.save(actionLogs);

        log.info(
                "Logging automatic trash deletion: entityId={}, entityType={}, details={}",
                entityId,
                entityType,
                detailsJson
        );
    }

    public void updateLog(
            String fileName,
            Long entityId,
            String entityType,
            String detailsJson
    ) {
        ActionLogs actionLogs = logAction(
                ActionType.UPDATE.name(),
                entityId,
                entityType,
                detailsJson
        );

        actionLogsRepository.save(actionLogs);

        log.info("Logging the update of {}", fileName);
    }

    public void favoritesAddLog(
            Long entityId,
            EntityType entityType
    ) {
        ActionLogs actionLogs = logAction(
                ActionType.FAVORITES_ADD.name(),
                entityId,
                entityType.name(),
                null
        );

        actionLogsRepository.save(actionLogs);

        log.info(
                "Added to favorites: entityId={}, entityType={}",
                entityId,
                entityType
        );
    }

    public void favoritesRemoveLog(
            Long entityId,
            EntityType entityType
    ) {
        ActionLogs actionLogs = logAction(
                ActionType.FAVORITES_REMOVE.name(),
                entityId,
                entityType.name(),
                null
        );

        actionLogsRepository.save(actionLogs);

        log.info(
                "Removed from favorites: entityId={}, entityType={}",
                entityId,
                entityType
        );
    }

    public void shareLog(
            Long entityId,
            EntityType entityType,
            Long shareId,
            Long sharedWithUserId,
            SharingRole role
    ) {
        String detailsJson = sharingDetails(
                shareId,
                sharedWithUserId,
                role
        );

        ActionLogs actionLogs = logAction(
                ActionType.SHARE.name(),
                entityId,
                entityType.name(),
                detailsJson
        );

        actionLogsRepository.save(actionLogs);

        log.info(
                "Shared resource: entityId={}, entityType={}, shareId={}, sharedWithUserId={}, role={}",
                entityId,
                entityType,
                shareId,
                sharedWithUserId,
                role
        );
    }

    public void shareRevokeLog(
            Long entityId,
            EntityType entityType,
            Long shareId,
            Long sharedWithUserId,
            SharingRole role
    ) {
        String detailsJson = sharingDetails(
                shareId,
                sharedWithUserId,
                role
        );

        ActionLogs actionLogs = logAction(
                ActionType.SHARE_REVOKE.name(),
                entityId,
                entityType.name(),
                detailsJson
        );

        actionLogsRepository.save(actionLogs);

        log.info(
                "Revoked share: entityId={}, entityType={}, shareId={}, sharedWithUserId={}, role={}",
                entityId,
                entityType,
                shareId,
                sharedWithUserId,
                role
        );
    }

    private String sharingDetails(
            Long shareId,
            Long sharedWithUserId,
            SharingRole role
    ) {
        return String.format(
                "{\"shareId\":%d,\"sharedWithUserId\":%d,\"role\":\"%s\"}",
                shareId,
                sharedWithUserId,
                role.name()
        );
    }
}
