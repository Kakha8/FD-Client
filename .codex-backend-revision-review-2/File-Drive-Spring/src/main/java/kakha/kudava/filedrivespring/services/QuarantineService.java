package kakha.kudava.filedrivespring.services;

import io.minio.MinioClient;
import io.minio.RemoveObjectArgs;
import kakha.kudava.filedrivespring.dto.ViewQuarantinedFilesDTO;
import kakha.kudava.filedrivespring.model.ActionLogs;
import kakha.kudava.filedrivespring.model.QuarantinedFiles;
import kakha.kudava.filedrivespring.repository.ActionLogsRepository;
import kakha.kudava.filedrivespring.repository.QuarantinedFilesRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import io.minio.GetObjectArgs;
import net.lingala.zip4j.ZipFile;
import net.lingala.zip4j.model.ZipParameters;
import net.lingala.zip4j.model.enums.AesKeyStrength;
import net.lingala.zip4j.model.enums.EncryptionMethod;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Optional;

@Slf4j
@Service
public class QuarantineService {

    private final QuarantinedFilesRepository quarantinedFilesRepository;
    private final MinioClient minioClient;
    private final String quarantineBucket;
    private final LogsService logsService;
    private final ActionLogsRepository actionLogsRepository;
    private final int retentionDays;

    public QuarantineService(QuarantinedFilesRepository quarantinedFilesRepository, MinioClient minioClient,
                             @Value("${s3.quarantine-bucket}") String quarantineBucket, LogsService logsService,
                             ActionLogsRepository actionLogsRepository, @Value("${quarantine.retention-days}") int retentionDays) {
        this.quarantinedFilesRepository = quarantinedFilesRepository;
        this.minioClient = minioClient;
        this.quarantineBucket = quarantineBucket;
        this.logsService = logsService;
        this.actionLogsRepository = actionLogsRepository;
        this.retentionDays = retentionDays;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public QuarantinedFiles save(QuarantinedFiles quarantinedFile) {
        return quarantinedFilesRepository.saveAndFlush(quarantinedFile);
    }

    @Transactional(readOnly = true)
    public List<ViewQuarantinedFilesDTO> viewQuarantine() {
        return quarantinedFilesRepository.findAll()
                .stream()
                .map(q -> new ViewQuarantinedFilesDTO(
                        q.getId(),
                        q.getOriginalFilename(),
                        q.getObjectKey(),
                        q.getContentType(),
                        q.getSize(),
                        q.getChecksum(),
                        q.getClamAvResponse(),
                        q.getParentFolderId(),
                        q.getUser().getId(),
                        q.getUser().getUsername(),
                        q.getCreatedAt()
                ))
                .toList();
    }

    @Transactional(readOnly = true)
    public ViewQuarantinedFilesDTO findQuarantinedFileById(Long id) {
        QuarantinedFiles q = quarantinedFilesRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Quarantined file not found: " + id));

        return new ViewQuarantinedFilesDTO(
                q.getId(),
                q.getOriginalFilename(),
                q.getObjectKey(),
                q.getContentType(),
                q.getSize(),
                q.getChecksum(),
                q.getClamAvResponse(),
                q.getParentFolderId(),
                q.getUser().getId(),
                q.getUser().getUsername(),
                q.getCreatedAt()
        );
    }

    public Path createPasswordProtectedZip(Long quarantineId) throws Exception {
        QuarantinedFiles q = quarantinedFilesRepository.findById(quarantineId)
                .orElseThrow(() -> new RuntimeException("Quarantined file not found: " + quarantineId));

        Path tempDir = Files.createTempDirectory("quarantine-download-");
        Path infectedFile = tempDir.resolve(q.getOriginalFilename());
        Path zipFile = tempDir.resolve("quarantine-" + q.getId() + ".zip");

        try (InputStream in = minioClient.getObject(
                GetObjectArgs.builder()
                        .bucket(quarantineBucket)
                        .object(q.getObjectKey())
                        .build()
        )) {
            Files.copy(in, infectedFile, StandardCopyOption.REPLACE_EXISTING);
        }

        ZipParameters zipParameters = new ZipParameters();
        zipParameters.setEncryptFiles(true);
        zipParameters.setEncryptionMethod(EncryptionMethod.AES);
        zipParameters.setAesKeyStrength(AesKeyStrength.KEY_STRENGTH_256);
        zipParameters.setFileNameInZip(q.getOriginalFilename());

        ZipFile zip = new ZipFile(zipFile.toFile(), "infected".toCharArray());
        zip.addFile(infectedFile.toFile(), zipParameters);

        return zipFile;
    }

    @Transactional
    public void deleteQuarantinedFile(Long quarantineId) {
        QuarantinedFiles file = quarantinedFilesRepository.findById(quarantineId)
                .orElseThrow(() -> new RuntimeException("Quarantined file not found: " + quarantineId));
        String objectKey = file.getObjectKey();
        try {
            minioClient.removeObject(
                    RemoveObjectArgs.builder()
                            .bucket(quarantineBucket)
                            .object(objectKey)
                            .build()
            );
            log.info("Object in quarantine bucket deleted successfully {}", objectKey);
            logsService.malwareDeleteLog(objectKey, quarantineId, "FILE");
            file.setDeleted(true);
            quarantinedFilesRepository.save(file);
        } catch (Exception e) {
            throw new RuntimeException("Failed to delete quarantined object: " + objectKey, e);
        }
        quarantinedFilesRepository.deleteById(quarantineId);

    }

    //@Scheduled(cron = "0 * * * * *")
    @Scheduled(cron = "0 0 3 * * *")
    @Transactional
    public void deleteExpiredQuarantinedFiles() {
        Instant cutoff = Instant.now().minus(retentionDays, ChronoUnit.DAYS);

        List<QuarantinedFiles> expiredFiles =
                quarantinedFilesRepository.findByCreatedAtBeforeAndDeletedFalse(cutoff);

        if (expiredFiles.isEmpty()) {
            log.info("No expired quarantined files found");
            return;
        }

        for (QuarantinedFiles file : expiredFiles) {
            String objectKey = file.getObjectKey();

            try {
                minioClient.removeObject(
                        RemoveObjectArgs.builder()
                                .bucket(quarantineBucket)
                                .object(objectKey)
                                .build()
                );

                file.setDeleted(true);
                quarantinedFilesRepository.save(file);

                log.warn(
                        "Deleted expired quarantined file: id={}, objectKey={}, createdAt={}",
                        file.getId(),
                        objectKey,
                        file.getCreatedAt()
                );
                logsService.malwareScheduleLog(objectKey, file.getId(), "FILE");
            } catch (Exception e) {
                log.error(
                        "Failed to delete expired quarantined file: id={}, objectKey={}",
                        file.getId(),
                        objectKey,
                        e
                );
            }
        }
    }
}
