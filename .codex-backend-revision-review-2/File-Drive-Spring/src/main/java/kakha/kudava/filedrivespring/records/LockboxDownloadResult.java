package kakha.kudava.filedrivespring.records;
import java.io.InputStream;
import java.util.Objects;

public record LockboxDownloadResult(
        String fileName,
        long size,
        String contentType,
        InputStream inputStream
) {
    public LockboxDownloadResult {
        if (fileName == null || fileName.isBlank()) {
            throw new IllegalArgumentException(
                    "Download filename is required."
            );
        }

        if (size < 0) {
            throw new IllegalArgumentException(
                    "Download size cannot be negative."
            );
        }

        if (contentType == null
                || contentType.isBlank()) {
            throw new IllegalArgumentException(
                    "Download content type is required."
            );
        }

        Objects.requireNonNull(
                inputStream,
                "inputStream"
        );
    }
}