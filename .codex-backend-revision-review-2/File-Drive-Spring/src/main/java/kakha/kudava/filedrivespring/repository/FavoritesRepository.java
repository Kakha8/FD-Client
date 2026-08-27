package kakha.kudava.filedrivespring.repository;

import kakha.kudava.filedrivespring.enums.EntityType;
import kakha.kudava.filedrivespring.model.Favorites;
import kakha.kudava.filedrivespring.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface FavoritesRepository extends JpaRepository<Favorites, Integer> {
    Optional<Favorites> findByUserAndEntityTypeAndEntityId(
            User user,
            EntityType entityType,
            Long entityId
    );

    List<Favorites> findAllByUserAndRemovedAtIsNullOrderByCreatedAtDesc(
            User user
    );

    Optional<Favorites> findByIdAndUser(
            Long id,
            User user
    );
}
