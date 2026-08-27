package kakha.kudava.filedrivespring.repository;

import jakarta.transaction.Transactional;
import kakha.kudava.filedrivespring.model.Notification;
import kakha.kudava.filedrivespring.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface NotificationRepository
        extends JpaRepository<Notification, Long> {

    /**
     * Returns active notifications for a recipient, newest first.
     *
     * Use PageRequest.of(0, 10) for the notification dropdown.
     */
    Page<Notification> findAllByRecipientAndRemovedAtIsNullOrderByCreatedAtDesc(
            User recipient,
            Pageable pageable
    );

    /**
     * Finds a notification only when it belongs to the recipient
     * and has not been removed.
     */
    Optional<Notification> findByIdAndRecipientAndRemovedAtIsNull(
            Long id,
            User recipient
    );

    /**
     * Used for the unread badge beside the bell.
     */
    long countByRecipientAndReadAtIsNullAndRemovedAtIsNull(
            User recipient
    );

    /**
     * Marks all active unread notifications for a user as read.
     */
    @Transactional
    @Modifying(
            clearAutomatically = true,
            flushAutomatically = true
    )
    @Query("""
            update Notification n
               set n.readAt = :readAt
             where n.recipient = :recipient
               and n.readAt is null
               and n.removedAt is null
            """)
    int markAllReadByRecipient(
            @Param("recipient") User recipient,
            @Param("readAt") Instant readAt
    );
}