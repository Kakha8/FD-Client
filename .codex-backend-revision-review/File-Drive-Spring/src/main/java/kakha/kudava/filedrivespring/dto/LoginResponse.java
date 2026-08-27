package kakha.kudava.filedrivespring.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.Objects;
import java.util.UUID;

@Getter
@Setter
public class LoginResponse {
    private String accessToken;
    private Long userId;
    private String username;
    private UUID publicUuid;

    public LoginResponse(String token, Long userId, String username, UUID publicUuid) {
        this.accessToken = token;
        this.userId = userId;
        this.username = username;
        this.publicUuid = Objects.requireNonNull(publicUuid, "publicUuid");
    }
}
