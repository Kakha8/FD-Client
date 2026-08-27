package kakha.kudava.filedrivespring.records;

import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

public record ZipDownloadResult(String fileName,
                                StreamingResponseBody responseBody
) {
}
