package kakha.kudava.filedrivespring.dto.lockbox;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record LockboxEnrollmentChallengeResponse(
        UUID enrollmentId,
        String challenge,
        Instant expiresAt
) {
    public LockboxEnrollmentChallengeResponse {
        Objects.requireNonNull(
                enrollmentId,
                "enrollmentId"
        );

        if (challenge == null || challenge.isBlank()) {
            throw new IllegalArgumentException(
                    "Enrollment challenge is required."
            );
        }

        Objects.requireNonNull(
                expiresAt,
                "expiresAt"
        );
    }
}