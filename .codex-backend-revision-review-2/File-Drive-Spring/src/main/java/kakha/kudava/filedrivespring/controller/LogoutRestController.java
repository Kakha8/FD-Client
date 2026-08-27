package kakha.kudava.filedrivespring.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kakha.kudava.filedrivespring.model.JwtRefresher;
import kakha.kudava.filedrivespring.services.jwt.JwtRefreshService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api/auth/logout")
public class LogoutRestController {


    private static final String REFRESH_COOKIE = "refresh_token";

    private final JwtRefreshService refreshService;

    public LogoutRestController(JwtRefreshService refreshService) {
        this.refreshService = refreshService;
    }

    @PostMapping
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {

        String rawRefresh = readCookie(request, REFRESH_COOKIE);
        log.info("Logout HIT!!");

        if (rawRefresh != null && !rawRefresh.isBlank()) {
            try {
                JwtRefresher stored = refreshService.validateToken(rawRefresh);
                log.info("Refresh token HIT!!");

                Long userId = stored.getUser().getId();
                int revokedCount = refreshService.revokeAllForUser(userId);

                log.info("Revoked {} refresh tokens for userId={}", revokedCount, userId);
            } catch (RuntimeException ignored) {
                // token already invalid / expired / revoked → still logout
            }
        }

        clearRefreshCookie(response);

        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }


    private String readCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (name.equals(c.getName())) return c.getValue();
        }
        return null;
    }

    private void clearRefreshCookie(HttpServletResponse response) {
        response.addHeader("Set-Cookie",
                REFRESH_COOKIE
                        + "=; Max-Age=0"
                        + "; Path=/api/auth"
                        + "; Secure"
                        + "; HttpOnly"
                        + "; SameSite=None");
    }

}
