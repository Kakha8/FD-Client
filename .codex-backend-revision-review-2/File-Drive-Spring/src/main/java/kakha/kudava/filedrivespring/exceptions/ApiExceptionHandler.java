package kakha.kudava.filedrivespring.exceptions;
import kakha.kudava.filedrivespring.records.ApiErrorResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(LockboxApiException.class)
    public ResponseEntity<ApiErrorResponse> handleLockbox(LockboxApiException ex) {
        return ResponseEntity.status(ex.getStatus()).body(ApiErrorResponse.of(ex.getCode(), ex.getMessage(), ex.getStatus().value()));
    }

    @ExceptionHandler(MalwareDetectedException.class)
    public ResponseEntity<ApiErrorResponse> handleMalwareDetected(MalwareDetectedException ex) {
        log.warn("Malware upload blocked: {}", ex.getMessage());

        return ResponseEntity
                .status(HttpStatus.UNPROCESSABLE_ENTITY)
                .body(ApiErrorResponse.of(
                        "MALWARE_DETECTED",
                        ex.getMessage(),
                        HttpStatus.UNPROCESSABLE_ENTITY.value()
                ));
    }

    @ExceptionHandler(UploadCanceledException.class)
    public ResponseEntity<ApiErrorResponse> handleUploadCanceled(UploadCanceledException ex) {
        log.info("Upload canceled: {}", ex.getMessage());

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(ApiErrorResponse.of(
                        "UPLOAD_CANCELED",
                        ex.getMessage(),
                        HttpStatus.CONFLICT.value()
                ));
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<ApiErrorResponse> handleRuntimeException(RuntimeException ex) {
        log.warn("Request failed: {}", ex.getMessage());

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(ApiErrorResponse.of(
                        "BAD_REQUEST",
                        ex.getMessage(),
                        HttpStatus.BAD_REQUEST.value()
                ));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleException(Exception ex) {
        log.error("Unexpected server error", ex);

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiErrorResponse.of(
                        "INTERNAL_SERVER_ERROR",
                        "Unexpected server error",
                        HttpStatus.INTERNAL_SERVER_ERROR.value()
                ));
    }

    @ExceptionHandler(ResponseStatusException.class)
    public ResponseEntity<ApiErrorResponse> handleResponseStatusException(ResponseStatusException ex) {
        int status = ex.getStatusCode().value();

        return ResponseEntity
                .status(status)
                .body(ApiErrorResponse.of(
                        ex.getStatusCode().toString(),
                        ex.getReason(),
                        status
                ));
    }
}
