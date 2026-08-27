package kakha.kudava.filedrivespring.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.minio.errors.*;
import jakarta.servlet.http.HttpServletResponse;
import kakha.kudava.filedrivespring.dto.*;
import kakha.kudava.filedrivespring.records.FolderDownloadResult;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import kakha.kudava.filedrivespring.repository.FolderRepository;
import kakha.kudava.filedrivespring.services.MoveService;
import kakha.kudava.filedrivespring.services.objects.ObjectStorageService;
import kakha.kudava.filedrivespring.services.objects.FolderService;
import kakha.kudava.filedrivespring.services.RenameService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/folders")
public class FoldersRestController {

    private final FolderService folderService;
    private final FolderRepository folderRepository;
    private final FileMetaDataRepository fileMetaDataRepository;
    private final RenameService renameService;
    private final MoveService moveService;
    private final ObjectStorageService objectStorageService;

    public FoldersRestController(FolderService folderService, FolderRepository folderRepository, FileMetaDataRepository fileMetaDataRepository, RenameService renameService, MoveService moveService, ObjectStorageService objectStorageService) {
        this.folderService = folderService;
        this.folderRepository = folderRepository;
        this.fileMetaDataRepository = fileMetaDataRepository;
        this.renameService = renameService;
        this.moveService = moveService;
        this.objectStorageService = objectStorageService;
    }

/*    @GetMapping
    public List<Folders> list() {
        return folderRepository.findAll();
    }*/

    @GetMapping("/{id}")
    public ResponseEntity<FolderViewDTO> get(@PathVariable Long id) {
        return ResponseEntity.ok(folderService.viewFolder(id));
    }

    @GetMapping("/{id}/download")
    public void download(
            @PathVariable Long id,
            HttpServletResponse response
    ) throws Exception {
        FolderDownloadResult result = folderService.downloadFolderAsZip(id);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(
                HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + result.fileName() + "\""
        );
        response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);
        result.responseBody().writeTo(response.getOutputStream());
    }

    @GetMapping("/root")
    public ResponseEntity<FolderViewDTO> getRoot(Authentication authentication) throws Exception {
        return ResponseEntity.ok(folderService.viewCurrentUserRoot());
    }

    @PostMapping
    public ResponseEntity<Map<String, String>> create(@RequestBody FolderCreateRequest req)
            throws Exception {
        FolderDTO folder = folderService.create(req);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("name", folder.getName(),
                        "prefix", folder.getPrefix()));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, String>> delete(@PathVariable("id") Long id) throws Exception {
        folderService.delete(id);
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @DeleteMapping("/delete/multiple")
    public ResponseEntity<Void> deleteMultiple(@RequestBody DeleteFoldersReqDTO reqDTO) throws Exception {
        folderService.deleteMultiple(reqDTO.getFolderIds());
        return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
    }

    @PutMapping("/{id}/rename")
    public ResponseEntity<Void> rename(@PathVariable Long id, @RequestBody RenameRequest req) throws InsufficientDataException,
            ErrorResponseException, JsonProcessingException {
        renameService.renameFolder(id, req.getNewName());
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{id}/move")
    public ResponseEntity<Void> moveFolder(@PathVariable Long id, @RequestBody MoveFolderRequest req){
        moveService.moveFolder(id, req.getTargetFolderId());
        return ResponseEntity.noContent().build();
    }

    @PutMapping("/{id}/copy")
    public ResponseEntity<Void> copyFolder(@PathVariable Long id, @RequestBody MoveFolderRequest req) {
        moveService.copyFolder(id, req.getTargetFolderId());
        return ResponseEntity.noContent().build();
    }

}
