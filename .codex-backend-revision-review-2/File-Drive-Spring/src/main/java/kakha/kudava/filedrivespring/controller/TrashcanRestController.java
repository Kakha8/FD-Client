package kakha.kudava.filedrivespring.controller;

import jakarta.servlet.http.HttpServletResponse;
import kakha.kudava.filedrivespring.dto.MoveToTrashReqDTO;
import kakha.kudava.filedrivespring.dto.TrashcanActionRequest;
import kakha.kudava.filedrivespring.dto.ViewTrashcanDTO;
import kakha.kudava.filedrivespring.services.TrashcanService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/trashcan")
public class TrashcanRestController {

    private final TrashcanService trashcanService;

    public TrashcanRestController(TrashcanService trashcanService) {
        this.trashcanService = trashcanService;
    }

    @GetMapping()
    public ViewTrashcanDTO trashcan() {
        ViewTrashcanDTO dto = trashcanService.viewTrashcan();
        return dto;
    }

    @PostMapping("/move")
    public ResponseEntity<Void> moveToTrash(@RequestBody MoveToTrashReqDTO req) throws Exception {
        trashcanService.moveToTrash(req);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/permanent")
    public ResponseEntity<Void> deletePermanently(@RequestBody TrashcanActionRequest request) {
        trashcanService.deletePermanently(request);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/clear")
    public ResponseEntity<Void> clearTrash() {
        trashcanService.clearTrash();
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/restore")
    public ResponseEntity<Void> restore(@RequestBody TrashcanActionRequest request) {
        trashcanService.restore(request);
        return ResponseEntity.noContent().build();
    }
}
