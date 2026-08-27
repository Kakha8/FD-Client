package kakha.kudava.filedrivespring.repository;

import kakha.kudava.filedrivespring.model.LockboxDevice;
import kakha.kudava.filedrivespring.model.LockboxProfile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface LockboxProfileRepository extends JpaRepository<LockboxProfile, Long> {
    Optional<LockboxProfile> findByUserId(Long userId);

    boolean existsByUserId(Long userId);
}
