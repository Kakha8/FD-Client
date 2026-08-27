package kakha.kudava.filedrivespring.services.users;

import kakha.kudava.filedrivespring.dto.RegisterDTO;
import kakha.kudava.filedrivespring.dto.UserDTO;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.UserRepository;
import kakha.kudava.filedrivespring.services.objects.RootFolderService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class RegistrationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RootFolderService rootFolderService;

    public RegistrationService(UserRepository userRepository, PasswordEncoder passwordEncoder, RootFolderService rootFolderService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.rootFolderService = rootFolderService;
    }

    public RegisterDTO saveUser(RegisterDTO registerDTO) {
        User user = new User();
        user.setUsername(registerDTO.getUsername());
        user.setPassword(passwordEncoder.encode(registerDTO.getPassword()));
        user.setRole(User.Role.valueOf("USER"));
        User saved = userRepository.save(user);

        rootFolderService.ensureRootFolder(saved);

        log.info("User saved successfully: {}", registerDTO.getUsername());
        return registerDTO;
    }

    public UserDTO saveUserAsAdmin(UserDTO userDTO) {
        User user = new User();
        user.setUsername(userDTO.getUsername());
        user.setPassword(passwordEncoder.encode(userDTO.getPassword()));

        if (userDTO.getRole() == null || userDTO.getRole().isBlank()) {
            user.setRole(User.Role.USER);
        } else {
            user.setRole(User.Role.valueOf(userDTO.getRole().trim().toUpperCase()));
        }

        User saved = userRepository.save(user);

        rootFolderService.ensureRootFolder(saved);

        log.info("User saved successfully: {}", userDTO.getUsername());
        return userDTO;
    }

}
