package kakha.kudava.filedrivespring.dto.lockbox;
import java.time.Instant;
import java.util.UUID;
public record LockboxUploadResponse(Long id, UUID clientFileId, long revision, Long parentId,
                                    long containerSize, String containerHash, int formatVersion,
                                    int suiteId, Instant createdAt) {}
