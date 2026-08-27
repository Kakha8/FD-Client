package kakha.kudava.filedrivespring.controller;

import kakha.kudava.filedrivespring.dto.FavoritesDTO;
import kakha.kudava.filedrivespring.dto.FavoritesRequestDTO;
import kakha.kudava.filedrivespring.model.Favorites;
import kakha.kudava.filedrivespring.services.FavoritesService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("api/favorites")
public class FavoritesRestController {

    private final FavoritesService favoritesService;

    public FavoritesRestController(FavoritesService favoritesService) {
        this.favoritesService = favoritesService;
    }

    @GetMapping
    public List<FavoritesDTO> getAll() {
        return favoritesService.getAll();
    }

    @PostMapping("/add")
    public ResponseEntity<List<Favorites>> addFavorite(@RequestBody FavoritesRequestDTO dto){
        favoritesService.add(dto);
        return ResponseEntity.ok().build();
    }

    @DeleteMapping("/{favoriteId}")
    public ResponseEntity<Void> removeFavorite(
            @PathVariable Long favoriteId
    ) {
        favoritesService.remove(favoriteId);
        return ResponseEntity.noContent().build();
    }
}
