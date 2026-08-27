package kakha.kudava.filedrivespring.services;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.minio.GetObjectArgs;
import io.minio.MinioClient;
import io.minio.PutObjectArgs;
import kakha.kudava.filedrivespring.dto.TextFileContentDTO;
import kakha.kudava.filedrivespring.dto.UpdateTextFileRequest;
import kakha.kudava.filedrivespring.enums.EntityType;
import kakha.kudava.filedrivespring.exceptions.MalwareDetectedException;
import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.time.Instant;

@Service
public class TextFileService {

    private static final Set<String> EDITABLE_EXTENSIONS = Set.of(
            "txt",
            "md",
            "csv",
            "json",
            "xml",
            "yaml",
            "yml",
            "properties",
            "ini",
            "log",
            "html",
            "css",
            "js",
            "ts",
            "java",
            "py",
            "sql"
    );

    private final MinioClient minioClient;
    private final String bucket;
    private final long maxBytes;
    private final FileMetaDataRepository fileMetaDataRepository;
    private final ResourceAccessService resourceAccessService;
    private final ClamAvScannerService clamAvScannerService;
    private final LogsService logsService;
    private final ObjectMapper objectMapper;

    public TextFileService(
            MinioClient minioClient,
            @Value("${s3.bucket}") String bucket,
            @Value("${app.text-editor.max-bytes:1048576}") long maxBytes,
            FileMetaDataRepository fileMetaDataRepository,
            ResourceAccessService resourceAccessService,
            ClamAvScannerService clamAvScannerService,
            LogsService logsService,
            ObjectMapper objectMapper
    ) {
        this.minioClient = minioClient;
        this.bucket = bucket;
        this.maxBytes = maxBytes;
        this.fileMetaDataRepository = fileMetaDataRepository;
        this.resourceAccessService = resourceAccessService;
        this.clamAvScannerService = clamAvScannerService;
        this.logsService = logsService;
        this.objectMapper = objectMapper;
    }

    public TextFileContentDTO getContent(Long fileId) throws Exception {
        FileMetaData file = resourceAccessService.requireFileView(fileId);

        requireEditableTextFile(file);

        byte[] bytes;

        try (InputStream inputStream = minioClient.getObject(
                GetObjectArgs.builder()
                        .bucket(bucket)
                        .object(file.getObjectKey())
                        .build()
        )) {
            bytes = readWithLimit(inputStream);
        }

        String content = decodeUtf8(bytes);

        return toDto(file, content);
    }

    public TextFileContentDTO updateContent(
            Long fileId,
            UpdateTextFileRequest request
    ) throws Exception {

        FileMetaData file = resourceAccessService.requireFileEdit(fileId);

        requireEditableTextFile(file);

        if (request == null || request.getContent() == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "content is required"
            );
        }

        checkExpectedChecksum(file, request.getExpectedChecksum());

        byte[] newBytes =
                request.getContent().getBytes(StandardCharsets.UTF_8);

        requireWithinLimit(newBytes.length);

        String newChecksum = sha256(newBytes);

        // Skip the MinIO write when the content has not changed.
        if (newChecksum.equalsIgnoreCase(file.getChecksum())) {
            return toDto(file, request.getContent());
        }

        scanContent(file, newBytes);

        String oldChecksum = file.getChecksum();
        Long oldSize = file.getSize();
        String contentType = resolveContentType(file.getFileName());

        replaceMinioObject(file, newBytes, contentType);

        file.setChecksum(newChecksum);
        file.setSize((long) newBytes.length);
        file.setObjectType(contentType);
        file.setLastModifiedDate(Instant.now());

        FileMetaData savedFile = fileMetaDataRepository.save(file);

        createUpdateLog(
                savedFile,
                oldChecksum,
                oldSize,
                newChecksum,
                newBytes.length
        );

        return toDto(savedFile, request.getContent());
    }

    private void replaceMinioObject(
            FileMetaData file,
            byte[] content,
            String contentType
    ) throws Exception {

        try (InputStream inputStream =
                     new ByteArrayInputStream(content)) {

            minioClient.putObject(
                    PutObjectArgs.builder()
                            .bucket(bucket)
                            .object(file.getObjectKey())
                            .stream(
                                    inputStream,
                                    content.length,
                                    -1
                            )
                            .contentType(contentType)
                            .build()
            );
        }
    }

    private void scanContent(
            FileMetaData file,
            byte[] content
    ) throws Exception {

        String extension = getExtension(file.getFileName());
        String suffix = extension.isBlank() ? ".txt" : "." + extension;

        Path temporaryFile =
                Files.createTempFile("text-edit-", suffix);

        try {
            Files.write(temporaryFile, content);

            ClamAvScannerService.ScanResult scanResult =
                    clamAvScannerService.scan(temporaryFile);

            if (!scanResult.clean()) {
                throw new MalwareDetectedException(
                        "Edit rejected: malware detected"
                );
            }
        } finally {
            Files.deleteIfExists(temporaryFile);
        }
    }

    private void checkExpectedChecksum(
            FileMetaData file,
            String expectedChecksum
    ) {
        if (expectedChecksum == null || expectedChecksum.isBlank()) {
            return;
        }

        if (!expectedChecksum.equalsIgnoreCase(file.getChecksum())) {
            throw new ResponseStatusException(
                    HttpStatus.CONFLICT,
                    "The file changed after you loaded it. " +
                            "Reload the content and try again."
            );
        }
    }

    private TextFileContentDTO toDto(
            FileMetaData file,
            String content
    ) {
        String contentType = file.getObjectType();

        if (contentType == null || contentType.isBlank()) {
            contentType = resolveContentType(file.getFileName());
        }

        return new TextFileContentDTO(
                file.getId(),
                file.getFileName(),
                contentType,
                StandardCharsets.UTF_8.name(),
                file.getSize(),
                file.getChecksum(),
                content
        );
    }

    private void requireEditableTextFile(FileMetaData file) {
        String extension = getExtension(file.getFileName());

        if (extension.isBlank()) {
            throw new ResponseStatusException(
                    HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                    "Files without an extension cannot be edited"
            );
        }

        if (!EDITABLE_EXTENSIONS.contains(extension)) {
            throw new ResponseStatusException(
                    HttpStatus.UNSUPPORTED_MEDIA_TYPE,
                    "Editing is not supported for ." + extension + " files"
            );
        }
    }

    private String getExtension(String fileName) {
        if (fileName == null || fileName.isBlank()) {
            return "";
        }

        int lastDot = fileName.lastIndexOf('.');

        if (lastDot < 0 || lastDot == fileName.length() - 1) {
            return "";
        }

        return fileName.substring(lastDot + 1)
                .toLowerCase(Locale.ROOT);
    }

    private String resolveContentType(String fileName) {
        return switch (getExtension(fileName)) {
            case "txt", "log", "ini", "properties" ->
                    "text/plain; charset=UTF-8";

            case "md" ->
                    "text/markdown; charset=UTF-8";

            case "csv" ->
                    "text/csv; charset=UTF-8";

            case "json" ->
                    "application/json; charset=UTF-8";

            case "xml" ->
                    "application/xml; charset=UTF-8";

            case "yaml", "yml" ->
                    "application/yaml; charset=UTF-8";

            case "html" ->
                    "text/html; charset=UTF-8";

            case "css" ->
                    "text/css; charset=UTF-8";

            case "js" ->
                    "text/javascript; charset=UTF-8";

            case "ts" ->
                    "application/typescript; charset=UTF-8";

            case "java" ->
                    "text/x-java-source; charset=UTF-8";

            case "py" ->
                    "text/x-python; charset=UTF-8";

            case "sql" ->
                    "application/sql; charset=UTF-8";

            default ->
                    "text/plain; charset=UTF-8";
        };
    }

    private byte[] readWithLimit(
            InputStream inputStream
    ) throws Exception {

        try (ByteArrayOutputStream outputStream =
                     new ByteArrayOutputStream()) {

            byte[] buffer = new byte[8192];
            long totalBytes = 0;
            int numberOfBytesRead;

            while ((numberOfBytesRead =
                    inputStream.read(buffer)) != -1) {

                totalBytes += numberOfBytesRead;
                requireWithinLimit(totalBytes);

                outputStream.write(
                        buffer,
                        0,
                        numberOfBytesRead
                );
            }

            return outputStream.toByteArray();
        }
    }

    private void requireWithinLimit(long byteCount) {
        if (byteCount > maxBytes) {
            throw new ResponseStatusException(
                    HttpStatus.PAYLOAD_TOO_LARGE,
                    "Text file exceeds the editor limit of " +
                            maxBytes + " bytes"
            );
        }
    }

    private String decodeUtf8(byte[] bytes) {
        try {
            return StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(
                            CodingErrorAction.REPORT
                    )
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();

        } catch (CharacterCodingException exception) {
            throw new ResponseStatusException(
                    HttpStatus.UNPROCESSABLE_ENTITY,
                    "The file is not valid UTF-8 text"
            );
        }
    }

    private String sha256(byte[] bytes) throws Exception {
        MessageDigest messageDigest =
                MessageDigest.getInstance("SHA-256");

        byte[] digest = messageDigest.digest(bytes);

        StringBuilder result =
                new StringBuilder(digest.length * 2);

        for (byte value : digest) {
            result.append(String.format("%02x", value));
        }

        return result.toString();
    }

    private void createUpdateLog(
            FileMetaData file,
            String oldChecksum,
            Long oldSize,
            String newChecksum,
            long newSize
    ) throws Exception {

        Map<String, Object> details = new LinkedHashMap<>();

        details.put("fileName", file.getFileName());
        details.put("oldChecksum", oldChecksum);
        details.put("newChecksum", newChecksum);
        details.put("oldSize", oldSize);
        details.put("newSize", newSize);

        logsService.updateLog(
                file.getFileName(),
                file.getId(),
                EntityType.FILE.name(),
                objectMapper.writeValueAsString(details)
        );
    }
}
