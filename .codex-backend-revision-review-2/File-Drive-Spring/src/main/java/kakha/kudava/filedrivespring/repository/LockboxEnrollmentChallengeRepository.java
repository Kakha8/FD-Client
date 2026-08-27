package kakha.kudava.filedrivespring.repository;

import jakarta.persistence.LockModeType;
import kakha.kudava.filedrivespring.model.LockboxEnrollmentChallenge;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface LockboxEnrollmentChallengeRepository
        extends JpaRepository<LockboxEnrollmentChallenge, Long> {
    Optional<LockboxEnrollmentChallenge>
    findByEnrollmentId(UUID enrollmentId);

    Optional<LockboxEnrollmentChallenge>
    findByEnrollmentIdAndUserId(
            UUID enrollmentId,
            Long userId
    );

    List<LockboxEnrollmentChallenge>
    findAllByUserIdAndStatus(
            Long userId,
            LockboxEnrollmentChallenge.Status status
    );

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
       select challenge
       from LockboxEnrollmentChallenge challenge
       where challenge.enrollmentId = :enrollmentId
         and challenge.user.id = :userId
       """)
    Optional<LockboxEnrollmentChallenge>
    findForCompletion(
            @Param("enrollmentId") UUID enrollmentId,
            @Param("userId") Long userId
    );
}
