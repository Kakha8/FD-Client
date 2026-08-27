package kakha.kudava.filedrivespring.controller;

import jakarta.servlet.http.HttpServletResponse;
import kakha.kudava.filedrivespring.dto.DownloadZipRequest;
import kakha.kudava.filedrivespring.records.ZipDownloadResult;
import kakha.kudava.filedrivespring.services.DownloadService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/download")
public class DownloadRestController {

    private final DownloadService downloadService;

    public DownloadRestController(DownloadService downloadService) {
        this.downloadService = downloadService;
    }

    @PostMapping("/zip")
    public void downloadZip(
            @RequestBody DownloadZipRequest request,
            HttpServletResponse response
    ) throws Exception {
        ZipDownloadResult result = downloadService.downloadAsZip(request);

        response.setStatus(HttpServletResponse.SC_OK);
        response.setHeader(
                HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + result.fileName() + "\""
        );
        response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);
        result.responseBody().writeTo(response.getOutputStream());
    }
}
