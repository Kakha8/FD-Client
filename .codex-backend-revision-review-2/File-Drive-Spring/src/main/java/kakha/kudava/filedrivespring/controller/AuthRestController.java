package kakha.kudava.filedrivespring.controller;

import jakarta.servlet.http.HttpServletResponse;
import kakha.kudava.filedrivespring.dto.LoginRequest;
import kakha.kudava.filedrivespring.dto.LoginResponse;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.services.jwt.JwtRefreshService;
import kakha.kudava.filedrivespring.services.jwt.JwtService;
import kakha.kudava.filedrivespring.services.users.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/api/auth")
public class AuthRestController {


    private static final String REFRESH_COOKIE = "refresh_token";
    private final int refreshDays;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final JwtRefreshService refreshService;
    private final UserService userService;

    public AuthRestController(@Value("${JWT_REFRESH_DAYS}") int refreshDays,
                              AuthenticationManager authenticationManager,
                              JwtService jwtService,
                              JwtRefreshService refreshService, UserService userService) {

        this.refreshDays = refreshDays;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshService = refreshService;
        this.userService = userService;
    }

    @GetMapping("/me")
    public Object me(Authentication auth) {
        return auth == null ? "NOT LOGGED IN" : auth.getName() + " " + auth.getAuthorities();
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest req, HttpServletResponse response) throws Exception {
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword())
        );

        UserDetails user = (UserDetails) auth.getPrincipal();

        String username = user.getUsername();
        User selectedUser = userService.getUserByEmail(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
        UUID publicUuid = requirePublicUuid(selectedUser);

        String token = jwtService.generateAccessToken(user); // includes roles claim

        String refreshToken = refreshService.createToken(selectedUser, refreshDays);
        setRefreshCookie(response, refreshToken, refreshDays);

        return ResponseEntity.ok(new LoginResponse(
                token,
                selectedUser.getId(),
                selectedUser.getUsername(),
                publicUuid
        ));
    }

    private UUID requirePublicUuid(User user) {
        if (user.getPublicUuid() == null) {
            throw new IllegalStateException("Authenticated account has no public UUID.");
        }
        return user.getPublicUuid();
    }

    private void setRefreshCookie(HttpServletResponse response, String token, int days) {
        int maxAge = (int) Duration.ofDays(days).getSeconds();

        log.info("Setting refresh cookie days={}, maxAgeSeconds={}", days, maxAge);

        response.addHeader("Set-Cookie",
                REFRESH_COOKIE + "=" + token
                        + "; Max-Age=" + maxAge
                        + "; Path=/api/auth"
                        + "; Secure"
                        + "; HttpOnly"
                        + "; SameSite=None");
    }

}
