package kakha.kudava.filedrivespring.controller;

import kakha.kudava.filedrivespring.dto.share.ShareRequestDTO;
import kakha.kudava.filedrivespring.dto.share.SharedItemDTO;
import kakha.kudava.filedrivespring.services.SharingService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/share")
public class SharingRestController {
    private final SharingService sharingService;


    public SharingRestController(SharingService sharingService) {
        this.sharingService = sharingService;
    }

    @GetMapping("/files/{fileId}")
    public ResponseEntity<List<SharedItemDTO>> getFileShares(@PathVariable Long fileId) {
        return ResponseEntity.ok(sharingService.getFileShares(fileId));
    }

    @GetMapping("/folders/{folderId}")
    public ResponseEntity<List<SharedItemDTO>> getFolderShares(@PathVariable Long folderId) {
        return ResponseEntity.ok(sharingService.getFolderShares(folderId));
    }



    @PostMapping
    public ResponseEntity<List<SharedItemDTO>> share(
            @RequestBody ShareRequestDTO request
    ) {
        return ResponseEntity.ok(
                sharingService.share(request)
        );
    }

    @DeleteMapping("/{shareId}")
    public ResponseEntity<Void> revokeShare(@PathVariable Long shareId) {
        sharingService.revokeShare(shareId);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/with-me")
    public ResponseEntity<List<SharedItemDTO>> getSharedWithMe() {
        return ResponseEntity.ok(sharingService.getSharedWithMe());
    }

    @GetMapping("/by-me")
    public ResponseEntity<List<SharedItemDTO>> getSharedByMe() {
        return ResponseEntity.ok(sharingService.getSharedByMe());
    }
}
