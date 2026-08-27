package kakha.kudava.filedrivespring.repository;

import kakha.kudava.filedrivespring.model.LockboxFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import jakarta.persistence.LockModeType;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface LockboxFileRepository
        extends JpaRepository<LockboxFile, Long> {

    Optional<LockboxFile> findByFileId(Long fileId);

    boolean existsByFileId(Long fileId);

    boolean existsByProfileIdAndClientFileId(Long profileId, UUID clientFileId);

    Optional<LockboxFile> findByIdAndProfileUserId(Long id, Long userId);
    List<LockboxFile> findAllByProfileUserIdOrderByCreatedAtDesc(
            Long userId
    );

    List<LockboxFile>
    findAllByProfileUserIdAndFileDeletedFalseAndFilePermanentlyDeletedFalseOrderByCreatedAtDesc(
            Long userId
    );

    Optional<LockboxFile> findByProfileIdAndClientFileId(Long profileId, UUID clientFileId);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<LockboxFile> findForUpdateByIdAndProfileUserId(Long id, Long userId);
}
