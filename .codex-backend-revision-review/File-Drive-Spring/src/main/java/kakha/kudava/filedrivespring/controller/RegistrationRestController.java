package kakha.kudava.filedrivespring.controller;

import kakha.kudava.filedrivespring.dto.RegisterDTO;
import kakha.kudava.filedrivespring.dto.UserDTO;
import kakha.kudava.filedrivespring.services.users.RegistrationService;
import kakha.kudava.filedrivespring.services.users.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

import static org.springframework.security.authorization.AuthorityReactiveAuthorizationManager.hasRole;

@RestController
@RequestMapping("/api/register")
public class RegistrationRestController {

    private final UserService userService;
    private final RegistrationService registrationService;

    public RegistrationRestController(UserService userService, RegistrationService registrationService) {
        this.userService = userService;
        this.registrationService = registrationService;
    }


    @PostMapping
    public ResponseEntity<Map<String, String>> addUser(@RequestBody RegisterDTO registerDTO) {
        RegisterDTO savedUser = registrationService.saveUser(registerDTO);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("Message" , "User added successfully!" ,
                        "Username", savedUser.getUsername() )
                );
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/as-admin")
    public ResponseEntity<Map<String, String>> addUserAsAdmin(@RequestBody UserDTO userDTO) {
        UserDTO savedUser = registrationService.saveUserAsAdmin(userDTO);
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("Message" , "User added successfully!" ,
                        "Username", savedUser.getUsername() )
                );
    }



}
