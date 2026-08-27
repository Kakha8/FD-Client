package kakha.kudava.filedrivespring.services;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
public class TrashCleanupScheduler {

    private final TrashcanService trashcanService;

    public TrashCleanupScheduler(TrashcanService trashcanService) {
        this.trashcanService = trashcanService;
    }

    //@Scheduled(cron = "*/15 * * * * *")
    @Scheduled(cron = "0 0 3 * * *")
    public void cleanupOldTrash() {
        trashcanService.permanentlyDeleteTrashOlderThan(Duration.ofDays(30));
    }
}