package kakha.kudava.filedrivespring.records;
import java.time.Instant;

public record ApiErrorResponse(
        String error,
        String message,
        int status,
        String timestamp
) {
    public static ApiErrorResponse of(String error, String message, int status) {
        return new ApiErrorResponse(
                error,
                message,
                status,
                Instant.now().toString()
        );
    }
}