package kakha.kudava.filedrivespring.dto.lockbox;
import java.time.Instant;
public record LockboxRevisionItemResponse(long revision,long containerSize,String containerHash,Instant createdAt,boolean current){}
