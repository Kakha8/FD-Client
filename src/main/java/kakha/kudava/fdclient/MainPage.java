package kakha.kudava.fdclient;

import kakha.kudava.fdclient.service.AuthService;

import java.util.Objects;

public class MainPage {
    private AuthService authService;

    public void setAuthService(AuthService authService) {
        this.authService = Objects.requireNonNull(
                authService,
                "authService"
        );
    }

    public AuthService getAuthService() {
        return authService;
    }
}
