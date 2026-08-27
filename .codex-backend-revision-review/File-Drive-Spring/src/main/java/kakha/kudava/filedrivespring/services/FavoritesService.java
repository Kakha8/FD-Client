package kakha.kudava.filedrivespring.services;

import kakha.kudava.filedrivespring.dto.FavoritesDTO;
import kakha.kudava.filedrivespring.dto.FavoritesRequestDTO;
import kakha.kudava.filedrivespring.enums.EntityType;
import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.Favorites;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import kakha.kudava.filedrivespring.repository.FavoritesRepository;
import kakha.kudava.filedrivespring.repository.FolderRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

@Service
public class FavoritesService {

    private final FavoritesRepository favoritesRepository;
    private final ResourceAccessService resourceAccessService;
    private final LogsService logsService;
    private final FileMetaDataRepository fileMetaDataRepository;
    private final FolderRepository folderRepository;

    public FavoritesService(
            FavoritesRepository favoritesRepository,
            ResourceAccessService resourceAccessService,
            LogsService logsService,
            FileMetaDataRepository fileMetaDataRepository,
            FolderRepository folderRepository
    ) {
        this.favoritesRepository = favoritesRepository;
        this.resourceAccessService = resourceAccessService;
        this.logsService = logsService;
        this.fileMetaDataRepository = fileMetaDataRepository;
        this.folderRepository = folderRepository;
    }

    @Transactional
    public void add(FavoritesRequestDTO request) {
        Objects.requireNonNull(request, "Favorites request cannot be null");

        User currentUser = resourceAccessService.currentUser();

        for (Long fileId : safeIds(request.getFileIds())) {
            resourceAccessService.requireFileView(fileId);

            boolean changed = addOrRestore(
                    currentUser,
                    EntityType.FILE,
                    fileId
            );

            if (changed) {
                logsService.favoritesAddLog(
                        fileId,
                        EntityType.FILE
                );
            }
        }

        for (Long folderId : safeIds(request.getFolderIds())) {
            resourceAccessService.requireFolderView(folderId);

            boolean changed = addOrRestore(
                    currentUser,
                    EntityType.FOLDER,
                    folderId
            );

            if (changed) {
                logsService.favoritesAddLog(
                        folderId,
                        EntityType.FOLDER
                );
            }
        }
    }

    private boolean addOrRestore(
            User user,
            EntityType entityType,
            Long entityId
    ) {
        return favoritesRepository
                .findByUserAndEntityTypeAndEntityId(
                        user,
                        entityType,
                        entityId
                )
                .map(favorite -> {
                    if (favorite.isActive()) {
                        return false;
                    }

                    favorite.restore();
                    return true;
                })
                .orElseGet(() -> {
                    favoritesRepository.save(
                            new Favorites(user, entityType, entityId)
                    );

                    return true;
                });
    }

    private List<Long> safeIds(List<Long> ids) {
        if (ids == null) {
            return Collections.emptyList();
        }

        return ids.stream()
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }

    @Transactional(readOnly = true)
    public List<FavoritesDTO> getAll() {
        User currentUser = resourceAccessService.currentUser();

        return favoritesRepository
                .findAllByUserAndRemovedAtIsNullOrderByCreatedAtDesc(currentUser)
                .stream()
                .map(this::toDto)
                .filter(Objects::nonNull)
                .toList();
    }

    private FavoritesDTO toDto(Favorites favorite) {
        Long entityId = favorite.getEntityId();

        if (favorite.getEntityType() == EntityType.FILE) {
            try {
                resourceAccessService.requireFileView(entityId);
            } catch (RuntimeException ignored) {
                return null;
            }

            FileMetaData file = fileMetaDataRepository
                    .findById(entityId)
                    .orElse(null);

            if (file == null
                    || file.isDeleted()
                    || file.isPermanentlyDeleted()) {
                return null;
            }

            FavoritesDTO dto = baseDto(favorite);
            dto.setName(file.getFileName());
            dto.setObjectType(file.getObjectType());
            dto.setSize(file.getSize());

            if (file.getOwner() != null) {
                dto.setOwnerUsername(file.getOwner().getUsername());
            }

            return dto;
        }

        if (favorite.getEntityType() == EntityType.FOLDER) {
            try {
                resourceAccessService.requireFolderView(entityId);
            } catch (RuntimeException ignored) {
                return null;
            }

            Folders folder = folderRepository
                    .findById(entityId)
                    .orElse(null);

            if (folder == null
                    || folder.isDeleted()
                    || folder.isPermanentlyDeleted()) {
                return null;
            }

            FavoritesDTO dto = baseDto(favorite);
            dto.setName(folder.getName());
            dto.setObjectType("folder");
            dto.setSize(null);

            if (folder.getOwner() != null) {
                dto.setOwnerUsername(folder.getOwner().getUsername());
            }

            return dto;
        }

        return null;
    }

    private FavoritesDTO baseDto(Favorites favorite) {
        FavoritesDTO dto = new FavoritesDTO();

        dto.setId(favorite.getId());
        dto.setEntityType(favorite.getEntityType());
        dto.setEntityId(favorite.getEntityId());
        dto.setCreatedAt(favorite.getCreatedAt());

        return dto;
    }

    @Transactional
    public void remove(Long favoriteId) {
        User currentUser = resourceAccessService.currentUser();

        Favorites favorite = favoritesRepository
                .findByIdAndUser(favoriteId, currentUser)
                .orElseThrow(() ->
                        new RuntimeException("Favorite not found")
                );

        if (!favorite.isActive()) {
            return;
        }

        favorite.remove();

        logsService.favoritesRemoveLog(
                favorite.getEntityId(),
                favorite.getEntityType()
        );
    }
}