package kakha.kudava.filedrivespring.repository;

import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.model.SharingPermission;
import kakha.kudava.filedrivespring.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface SharingPermissionRepository extends JpaRepository<SharingPermission, Long> {
    Optional<SharingPermission> findByFileAndSharedWith(
            FileMetaData file,
            User sharedWith
    );

    Optional<SharingPermission> findByFolderAndSharedWith(
            Folders folder,
            User sharedWith
    );

    Optional<SharingPermission> findByFileAndSharedWithAndActiveTrue(
            FileMetaData file,
            User sharedWith
    );

    Optional<SharingPermission> findByFolderAndSharedWithAndActiveTrue(
            Folders folder,
            User sharedWith
    );

    List<SharingPermission> findBySharedWithAndActiveTrue(User sharedWith);

    List<SharingPermission> findByOwnerAndActiveTrue(User owner);

    boolean existsByFolderAndActiveTrue(Folders current);

    boolean existsByFileAndActiveTrue(FileMetaData file);

    List<SharingPermission> findByFileAndActiveTrue(FileMetaData file);

    List<SharingPermission> findByFolderAndActiveTrue(Folders folder);
}
