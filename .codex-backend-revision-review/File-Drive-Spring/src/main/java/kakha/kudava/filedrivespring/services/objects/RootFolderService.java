package kakha.kudava.filedrivespring.services.objects;


import jakarta.transaction.Transactional;
import kakha.kudava.filedrivespring.enums.DriveSpace;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.FolderRepository;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
public class RootFolderService {

    private final FolderRepository folderRepository;

    public RootFolderService(FolderRepository folderRepository) {
        this.folderRepository = folderRepository;
    }

    /**
     * Compatibility method for all existing normal Drive callers.
     *
     * Existing code that calls ensureRootFolder(user) continues to
     * resolve the user's normal DRIVE root.
     */
    @Transactional
    public Folders ensureRootFolder(User user) {
        return ensureRootFolder(user, DriveSpace.DRIVE);
    }

    /**
     * Finds or creates the root folder for the requested Drive space.
     */
    @Transactional
    public Folders ensureRootFolder(
            User user,
            DriveSpace driveSpace
    ) {
        Objects.requireNonNull(user, "user");
        Objects.requireNonNull(driveSpace, "driveSpace");

        if (user.getId() == null) {
            throw new IllegalArgumentException(
                    "User must be persisted before creating a root folder."
            );
        }

        return folderRepository
                .findByOwnerAndParentIsNullAndDriveSpaceAndDeletedFalseAndPermanentlyDeletedFalse(
                        user,
                        driveSpace
                )
                .orElseGet(() -> createRootFolder(user, driveSpace));
    }

    /**
     * Convenience method for Lockbox services and controllers.
     */
    @Transactional
    public Folders ensureLockboxRootFolder(User user) {
        return ensureRootFolder(user, DriveSpace.LOCKBOX);
    }

    private Folders createRootFolder(
            User user,
            DriveSpace driveSpace
    ) {
        Folders root = new Folders();

        root.setName(rootName(driveSpace));
        root.setPrefix(rootPrefix(user, driveSpace));
        root.setOwner(user);
        root.setParent(null);
        root.setDriveSpace(driveSpace);
        root.setDeleted(false);
        root.setDeletedAt(null);
        root.setPermanentlyDeleted(false);
        root.setPermanentlyDeletedAt(null);

        return folderRepository.save(root);
    }

    private String rootName(DriveSpace driveSpace) {
        return switch (driveSpace) {
            case DRIVE -> "My Drive";
            case LOCKBOX -> "Lockbox";
        };
    }

    private String rootPrefix(
            User user,
            DriveSpace driveSpace
    ) {
        return switch (driveSpace) {
            /*
             * Preserve the existing normal Drive prefix so current object
             * keys and existing normal Drive behavior are not changed.
             */
            case DRIVE -> "users/" + user.getId() + "/";

            /*
             * Keep the Lockbox hierarchy outside the normal Drive prefix.
             * This prevents prefix-based Drive operations from accidentally
             * matching Lockbox folders.
             */
            case LOCKBOX -> "lockbox/users/" + user.getId() + "/";
        };
    }
}