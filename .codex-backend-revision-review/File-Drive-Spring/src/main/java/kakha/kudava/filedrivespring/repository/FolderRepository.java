package kakha.kudava.filedrivespring.repository;

import kakha.kudava.filedrivespring.enums.DriveSpace;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.model.User;
import org.jetbrains.annotations.NotNull;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface FolderRepository
        extends JpaRepository<Folders, Long> {

    Folders findFolderById(Long id);

    @Override
    @NotNull
    List<Folders> findAll();

    @Query("""
            select f.prefix
            from Folders f
            where f.id = :id
            """)
    String findPrefixById(@Param("id") Long id);

    @Modifying(
            clearAutomatically = true,
            flushAutomatically = true
    )
    @Query("""
            update Folders f
            set f.deleted = true
            where f.deleted = false
              and f.prefix like concat(:prefix, '%')
            """)
    int softDeleteTreeByPrefix(
            @Param("prefix") String prefix
    );

    List<Folders> findFoldersByParent_Id(Long parentId);

    List<Folders> findByPrefixStartingWithAndDeletedFalse(
            String prefix
    );

    Optional<Folders> findByPrefix(String prefix);

    /*
     * A user may have both a DRIVE root and a LOCKBOX root.
     *
     * Therefore root lookup must always include DriveSpace.
     */
    Optional<Folders>
    findByOwnerAndParentIsNullAndDriveSpaceAndDeletedFalseAndPermanentlyDeletedFalse(
            User owner,
            DriveSpace driveSpace
    );

    Optional<Folders> findByIdAndOwnerAndDeletedFalse(
            Long id,
            User owner
    );

    List<Folders>
    findFoldersByParent_IdAndOwnerAndDeletedFalse(
            Long parentId,
            User owner
    );

    Optional<Folders> findByPrefixAndDeletedFalse(
            String rootPrefix
    );

    List<Folders> findByParentId(Long id);

    List<Folders> findByOwnerAndPrefixStartingWith(
            User user,
            String prefix
    );

    Optional<Folders> findByPrefixAndOwnerAndDeletedFalse(
            String prefix,
            User owner
    );

    List<Folders> findByOwnerAndDeletedTrue(
            User owner
    );

    Optional<Folders> findByIdAndDeletedTrueAndOwner(
            Long id,
            User owner
    );

    List<Folders>
    findByOwnerAndDeletedTrueAndPrefixStartingWith(
            User owner,
            String prefix
    );

    Optional<Folders>
    findByPrefixAndOwnerAndDeletedFalseAndPermanentlyDeletedFalse(
            String prefix,
            User owner
    );

    List<Folders>
    findByOwnerAndDeletedTrueAndPermanentlyDeletedFalse(
            User owner
    );

    Optional<Folders>
    findByIdAndDeletedTrueAndPermanentlyDeletedFalseAndOwner(
            Long id,
            User owner
    );

    List<Folders>
    findByOwnerAndDeletedTrueAndPermanentlyDeletedFalseAndPrefixStartingWith(
            User owner,
            String prefix
    );

    List<Folders>
    findByDeletedTrueAndPermanentlyDeletedFalseAndDeletedAtBefore(
            Instant cutoff
    );

    Optional<Folders>
    findByPrefixAndOwnerAndDriveSpaceAndDeletedFalseAndPermanentlyDeletedFalse(
            String prefix,
            User owner,
            DriveSpace driveSpace
    );
}