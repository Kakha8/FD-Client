package kakha.kudava.filedrivespring.controller;

import kakha.kudava.filedrivespring.services.UploadCancellationService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/api/uploads")
public class UploadCancellationController {

    private final UploadCancellationService uploadCancellationService;

    public UploadCancellationController(UploadCancellationService uploadCancellationService) {
        this.uploadCancellationService = uploadCancellationService;
    }

    @DeleteMapping("/{uploadId}")
    public ResponseEntity<Void> cancelUpload(@PathVariable String uploadId) {
        log.info("Cancel upload requested: uploadId={}", uploadId);
        uploadCancellationService.cancel(uploadId);
        return ResponseEntity.noContent().build();
    }

}
