package kakha.kudava.filedrivespring.exceptions;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class LockboxApiException extends RuntimeException {
    private final String code;
    private final HttpStatus status;
    public LockboxApiException(String code, HttpStatus status, String message) { super(message); this.code=code; this.status=status; }
    public static LockboxApiException bad(String code, String message) { return new LockboxApiException(code, HttpStatus.BAD_REQUEST, message); }
}
