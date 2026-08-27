package kakha.kudava.filedrivespring.repository;

import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface FileMetaDataRepository extends JpaRepository<FileMetaData, Long> {
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
        update FileMetaData m
        set m.deleted = true
        where m.deleted = false
          and m.parent.prefix like concat(:prefix, '%')
    """)
    int softDeleteFilesByFolderPrefix(@Param("prefix") String prefix);


    List<FileMetaData> findByObjectKeyStartingWithAndDeletedFalse(String prefix);
    Optional<FileMetaData> findByObjectKey(String objectKey);

    List<FileMetaData> findAllByParentId(Long parentId);

    List<FileMetaData> findByParentId(Long id);

    List<FileMetaData> findByParent_IdAndDeletedFalse(Long parentId);

    boolean existsByObjectKeyAndDeletedFalseAndPermanentlyDeletedFalse(String objectKey);



    List<FileMetaData> findByDeletedTrueAndPermanentlyDeletedFalseAndDeletedAtBefore(
            Instant cutoff
    );

    List<FileMetaData> findByOwnerAndDeletedTrueAndPermanentlyDeletedFalse(User owner);

    Optional<FileMetaData> findByIdAndDeletedTrueAndPermanentlyDeletedFalseAndOwner(
            Long id,
            User owner
    );

    @Query("""
        select f from FileMetaData f
        where f.owner = :owner
          and f.deleted = false
          and f.permanentlyDeleted = false
          and f.driveSpace = kakha.kudava.filedrivespring.enums.DriveSpace.DRIVE
        order by coalesce(f.lastModifiedDate, f.creationDate) desc
    """)
    List<FileMetaData> findRecentFiles(@Param("owner") User owner, Pageable pageable);

    List<FileMetaData> findByOwnerAndDeletedTrueAndPermanentlyDeletedFalseAndOriginalObjectKeyStartingWith(
            User owner,
            String originalObjectKey
    );


}
