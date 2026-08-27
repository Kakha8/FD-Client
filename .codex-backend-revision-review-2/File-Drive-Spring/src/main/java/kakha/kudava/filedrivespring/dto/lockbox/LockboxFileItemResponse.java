package kakha.kudava.filedrivespring.dto.lockbox;
import java.time.Instant;
import java.util.UUID;
public record LockboxFileItemResponse(Long id, UUID clientFileId, long revision, long containerSize,
                                      Instant createdAt, int formatVersion, int suiteId) {}
