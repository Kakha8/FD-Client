package kakha.kudava.filedrivespring.services.jwt;

import kakha.kudava.filedrivespring.model.JwtRefresher;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.JwtRefresherRepository;
import kakha.kudava.filedrivespring.security.TokenHashUtil;
import kakha.kudava.filedrivespring.services.users.UserService;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
public class JwtRefreshService {

    private final UserService userService;
    private final JwtRefresherRepository repo;
    private static final SecureRandom random = new SecureRandom();

    public JwtRefreshService(UserService userService, JwtRefresherRepository jwtRefresherRepository) {
        this.userService = userService;
        this.repo = jwtRefresherRepository;
    }

    public String createToken(User user, int daysValid) {
        String refreshToken = generateRandomToken();
        String hash = TokenHashUtil.sha256(refreshToken);

        JwtRefresher entity = new JwtRefresher();
        entity.setUser(user);
        entity.setTokenHash(hash);
        entity.setExpiresAt(LocalDateTime.now().plusDays(daysValid));
        entity.setRevoked(false);

        repo.save(entity);
        return refreshToken;
    }

    public JwtRefresher validateToken(String token) {
        String hashedToken = TokenHashUtil.sha256(token);
        JwtRefresher stored = repo.findByTokenHashAndRevokedFalse(hashedToken)
                .orElseThrow(() -> new RuntimeException("Invalid refresh token"));

        if (stored.getExpiresAt().isBefore(LocalDateTime.now())) {
            stored.setRevoked(true);
            repo.save(stored);
            throw new RuntimeException("Refresh token expired");
        }
        stored.setLastUsedAt(LocalDateTime.now());
        repo.save(stored);

        return stored;
    }

    public void revoke(JwtRefresher refresher) {
        refresher.setRevoked(true);
        repo.save(refresher);
    }

    public int revokeAllForUser(Long userId) {
        return repo.revokeAllActiveByUserId(userId);
    }
    private String generateRandomToken() {
        byte[] bytes = new byte[64];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

}
