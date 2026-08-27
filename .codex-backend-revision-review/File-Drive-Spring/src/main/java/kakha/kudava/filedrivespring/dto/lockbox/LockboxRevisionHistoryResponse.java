package kakha.kudava.filedrivespring.dto.lockbox;
import java.util.List; import java.util.UUID;
public record LockboxRevisionHistoryResponse(Long fileId,UUID clientFileId,long currentRevision,List<LockboxRevisionItemResponse> revisions){public LockboxRevisionHistoryResponse{revisions=List.copyOf(revisions);}}
