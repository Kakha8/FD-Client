package kakha.kudava.filedrivespring.controller;

import kakha.kudava.filedrivespring.dto.lockbox.LockboxEnrollmentChallengeResponse;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxEnrollmentBeginRequest;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxEnrollmentCompleteRequest;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxEnrollmentCompleteResponse;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxStatusResponse;
import kakha.kudava.filedrivespring.services.lockbox.LockboxEnrollmentService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api/lockbox/enrollments")
public class LockboxEnrollmentController {

    private final LockboxEnrollmentService enrollmentService;

    public LockboxEnrollmentController(
            LockboxEnrollmentService enrollmentService
    ) {
        this.enrollmentService = enrollmentService;
    }


    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public LockboxEnrollmentChallengeResponse beginEnrollment(
            @RequestBody LockboxEnrollmentBeginRequest request
    ) {
        return enrollmentService.beginEnrollment(request);
    }

    @PostMapping("/{enrollmentId}/complete")
    public LockboxEnrollmentCompleteResponse completeEnrollment(
            @PathVariable UUID enrollmentId,
            @RequestBody LockboxEnrollmentCompleteRequest request
    ) {
        return enrollmentService.completeEnrollment(
                enrollmentId,
                request
        );
    }

    @GetMapping("/status")
    public LockboxStatusResponse getStatus(
            @RequestParam UUID deviceId
    ) {
        return enrollmentService.getStatus(deviceId);
    }
}
