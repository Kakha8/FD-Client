package kakha.kudava.filedrivespring.records;

import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

public record FolderDownloadResult(String fileName, StreamingResponseBody responseBody) {
}
