package kakha.kudava.filedrivespring.repository;

import kakha.kudava.filedrivespring.model.LockboxDevice;
import kakha.kudava.filedrivespring.model.LockboxKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface LockboxKeyRepository
        extends JpaRepository<LockboxKey, Long> {

    Optional<LockboxKey> findByKeyId(byte[] keyId);

    boolean existsByKeyId(byte[] keyId);

    List<LockboxKey> findAllByDeviceId(Long deviceId);

    Optional<LockboxKey> findByDeviceIdAndRoleAndStatus(
            Long deviceId,
            LockboxKey.Role role,
            LockboxKey.Status status
    );

    List<LockboxKey> findAllByDeviceProfileIdAndRoleAndStatus(
            Long profileId, LockboxKey.Role role, LockboxKey.Status status);

    List<LockboxKey>
    findAllByDeviceProfileUserIdAndDeviceStatusAndRoleAndStatus(
            Long userId,
            LockboxDevice.Status deviceStatus,
            LockboxKey.Role role,
            LockboxKey.Status keyStatus
    );

    @Query("""
        select k from LockboxKey k
        join fetch k.device d
        join d.profile p
        where p.user.id = :userId
          and d.status = :deviceStatus
          and k.role = :role
          and k.algorithm = :algorithm
          and k.status = :keyStatus
        order by d.createdAt asc, d.deviceUuid asc, k.createdAt asc
        """)
    List<LockboxKey> findOwnedActiveEncryptionKeys(
            @Param("userId") Long userId,
            @Param("deviceStatus") LockboxDevice.Status deviceStatus,
            @Param("role") LockboxKey.Role role,
            @Param("algorithm") LockboxKey.Algorithm algorithm,
            @Param("keyStatus") LockboxKey.Status keyStatus
    );
}
