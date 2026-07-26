package kakha.kudava.fdclient.security;

import java.util.Optional;

public interface RefreshTokenStore {

    void save(String refreshToken);

    Optional<String> load();

    void delete();
}