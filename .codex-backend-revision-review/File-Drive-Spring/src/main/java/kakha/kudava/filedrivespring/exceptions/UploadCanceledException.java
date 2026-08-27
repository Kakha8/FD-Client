package kakha.kudava.filedrivespring.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.CONFLICT)
public class UploadCanceledException extends RuntimeException {
    public UploadCanceledException(String message) {
        super(message);
    }
}
