package kakha.kudava.filedrivespring.repository;

import kakha.kudava.filedrivespring.model.LockboxDevice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface LockboxDeviceRepository extends JpaRepository<LockboxDevice, Long> {
    Optional<LockboxDevice> findByDeviceUuid(
            UUID deviceUuid
    );

    Optional<LockboxDevice>
    findByDeviceUuidAndProfileUserId(
            UUID deviceUuid,
            Long userId
    );

    List<LockboxDevice> findAllByProfileId(
            Long profileId
    );

    Optional<LockboxDevice> findByProfileIdAndDeviceUuid(
            Long profileId,
            UUID deviceUuid
    );
    Optional<LockboxDevice> findByProfileIdAndInstallationHandle(
            Long profileId,
            byte[] installationHandle
    );
    boolean existsByDeviceUuid(UUID deviceUuid);

    @Query("""
        select d from LockboxDevice d
        join fetch d.profile p
        where p.user.id = :userId
          and (:excludeDeviceId is null or d.deviceUuid <> :excludeDeviceId)
        order by d.createdAt asc, d.deviceUuid asc
        """)
    List<LockboxDevice> findOwnedDevices(
            @Param("userId") Long userId,
            @Param("excludeDeviceId") UUID excludeDeviceId
    );

    @Query("""
        select d from LockboxDevice d
        join fetch d.profile p
        where d.deviceUuid = :deviceUuid
          and p.user.id = :userId
          and d.status = :status
        """)
    Optional<LockboxDevice> findOwnedActiveDevice(
            @Param("deviceUuid") UUID deviceUuid,
            @Param("userId") Long userId,
            @Param("status") LockboxDevice.Status status
    );
}
