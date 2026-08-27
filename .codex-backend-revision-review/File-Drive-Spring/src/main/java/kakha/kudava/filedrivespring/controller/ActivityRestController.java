package kakha.kudava.filedrivespring.controller;
import kakha.kudava.filedrivespring.dto.ActivityItem;
import kakha.kudava.filedrivespring.enums.ActionType;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.services.ResourceAccessService;
import kakha.kudava.filedrivespring.services.notifications.ActivityService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;

@RestController
@RequestMapping("/api/activity")
public class ActivityRestController {

    private static final int MAX_PAGE_SIZE = 50;

    private final ActivityService activityService;
    private final ResourceAccessService resourceAccessService;

    public ActivityRestController(
            ActivityService activityService,
            ResourceAccessService resourceAccessService
    ) {
        this.activityService = activityService;
        this.resourceAccessService = resourceAccessService;
    }

    @GetMapping
    public ResponseEntity<ActivityPageResponse> getRecentActivity(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @RequestParam(required = false) Set<ActionType> types
    ) {
        if (
                from != null &&
                        to != null &&
                        !from.isBefore(to)
        ) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "'from' must be earlier than 'to'"
            );
        }

        User currentUser =
                resourceAccessService.currentUser();

        int safePage =
                Math.max(page, 0);

        int safeSize =
                Math.min(
                        Math.max(size, 1),
                        MAX_PAGE_SIZE
                );

        Page<ActivityItem> result =
                activityService.getRecentActivity(
                        currentUser,
                        PageRequest.of(
                                safePage,
                                safeSize,
                                Sort.by(
                                        Sort.Direction.DESC,
                                        "timestamp"
                                )
                        ),
                        from,
                        to,
                        types == null
                                ? Set.of()
                                : types
                );

        return ResponseEntity.ok(
                new ActivityPageResponse(
                        result.getContent(),
                        result.getNumber(),
                        result.getSize(),
                        result.getTotalElements(),
                        result.getTotalPages(),
                        result.hasNext()
                )
        );
    }

    @GetMapping("/types")
    public ResponseEntity<List<ActivityTypeOption>>
    getActivityTypes() {

        List<ActivityTypeOption> options =
                Arrays.stream(ActionType.values())
                        .filter(type ->
                                type != ActionType.DELETE
                        )
                        .map(type ->
                                new ActivityTypeOption(
                                        type,
                                        humanize(type.name())
                                )
                        )
                        .toList();

        return ResponseEntity.ok(options);
    }

    private static String humanize(
            String value
    ) {
        String text =
                value
                        .toLowerCase(Locale.ROOT)
                        .replace('_', ' ');

        return Character.toUpperCase(
                text.charAt(0)
        ) + text.substring(1);
    }

    public record ActivityPageResponse(
            List<ActivityItem> activities,
            int page,
            int size,
            long totalElements,
            int totalPages,
            boolean hasNext
    ) {
    }

    public record ActivityTypeOption(
            ActionType value,
            String label
    ) {
    }
}