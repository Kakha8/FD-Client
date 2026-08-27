package kakha.kudava.filedrivespring.services;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
@Service
public class UploadCancellationService {

    private final Set<String> canceledUploadIds = ConcurrentHashMap.newKeySet();

    public void cancel(String uploadId) {
        if (uploadId != null && !uploadId.isBlank()) {
            canceledUploadIds.add(uploadId);
            log.info("Upload marked as canceled: uploadId={}", uploadId);
        }
    }

    public boolean isCanceled(String uploadId) {
        return uploadId != null && canceledUploadIds.contains(uploadId);
    }

    public void clear(String uploadId) {
        if (uploadId != null) {
            canceledUploadIds.remove(uploadId);
        }
    }
}