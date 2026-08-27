package kakha.kudava.filedrivespring.repository;

import kakha.kudava.filedrivespring.model.LockboxShareEnvelope;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface LockboxShareEnvelopeRepository
        extends JpaRepository<LockboxShareEnvelope, Long> {

    List<LockboxShareEnvelope>
    findAllByShareIdOrderByCreatedAtAsc(
            Long shareId
    );

    Optional<LockboxShareEnvelope>
    findByShareIdAndRecipientKeyId(
            Long shareId,
            Long recipientKeyId
    );

    Optional<LockboxShareEnvelope>
    findByShareIdAndRecipientKeyKeyId(
            Long shareId,
            byte[] recipientKeyId
    );

    boolean existsByShareIdAndRecipientKeyId(
            Long shareId,
            Long recipientKeyId
    );

    long deleteAllByShareId(
            Long shareId
    );

    Optional<LockboxShareEnvelope> findByShareId(
            Long shareId
    );
}