package kakha.kudava.filedrivespring.dto;

import lombok.Getter;
import lombok.Setter;
import org.springframework.web.bind.annotation.GetMapping;

@Getter
@Setter
public class UserDTO {
    private Long id;
    private String username;
    private String password;
    private String role;
}
