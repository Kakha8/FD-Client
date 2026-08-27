package kakha.kudava.filedrivespring.controller;

import io.minio.MinioClient;
import kakha.kudava.filedrivespring.dto.ViewQuarantinedFilesDTO;
import kakha.kudava.filedrivespring.services.QuarantineService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;


@RestController
@RequestMapping("/api/quarantine")
public class QuarantineRestController {

    private final QuarantineService quarantineService;



    public QuarantineRestController(QuarantineService quarantineService) {
        this.quarantineService = quarantineService;
    }

    @GetMapping
    public List<ViewQuarantinedFilesDTO> viewQuarantine() {
        return quarantineService.viewQuarantine();
    }

    @GetMapping("/{id}")
    public ViewQuarantinedFilesDTO findQuarantinedFileById(@PathVariable Long id) {
        return quarantineService.findQuarantinedFileById(id);
    }

    @GetMapping("/{id}/download")
    public ResponseEntity<Resource> downloadQuarantinedFile(@PathVariable Long id) throws Exception {
        Path zipPath = quarantineService.createPasswordProtectedZip(id);

        Resource resource = new FileSystemResource(zipPath);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + zipPath.getFileName().toString() + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(Files.size(zipPath))
                .body(resource);
    }

    @DeleteMapping("/{id}")
    public void deleteQuarantinedFile(@PathVariable Long id) {
        quarantineService.deleteQuarantinedFile(id);
    }
}
