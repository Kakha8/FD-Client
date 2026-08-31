package kakha.kudava.fdclient.service;

import kakha.kudava.fdclient.security.RefreshTokenStore;
import org.junit.jupiter.api.Test;
import java.net.URI;
import java.net.HttpCookie;
import java.net.http.*;
import java.time.Instant;
import java.util.*;
import javax.net.ssl.SSLSession;
import static org.junit.jupiter.api.Assertions.*;

class AuthServiceMfaTest {
    private final MemoryStore store = new MemoryStore();
    private final AuthService auth = new AuthService(store, () -> {}, id -> {});

    @Test void challengeDoesNotActivateAccountOrRetainRefreshToken() {
        store.value = "old-refresh";
        var result = auth.handleInitialLoginResponse(response(200, challenge(Instant.now().plusSeconds(180))));
        assertTrue(result.mfaRequired());
        assertFalse(auth.isAuthenticated());
        assertNull(auth.getAccessToken());
        assertNull(store.value);
        auth.cancelMfa();
        assertTrue(auth.completeMfa("012345").isCompletedExceptionally());
    }

    @Test void malformedOrExpiredChallengesFailClosedWithoutLeakingBody() {
        for (String body : List.of(challenge(Instant.EPOCH), "{\"mfaRequired\":true,\"challengeToken\":\"private-value\"}",
                "{\"mfaRequired\":true,broken-private-value")) {
            var error = assertThrows(AuthService.AuthException.class,
                    () -> auth.handleInitialLoginResponse(response(200, body)));
            assertFalse(error.getMessage().contains("private-value"));
            assertFalse(auth.isAuthenticated());
        }
    }

    @Test void passwordOnlyLoginStillRequiresAndStoresRefreshCookie() {
        String body = "{\"accessToken\":\"test-access\",\"userId\":1,\"username\":\"alice\","
                + "\"publicUuid\":\"8c98baef-9c78-45d3-8797-b27e9786fa26\"}";
        assertThrows(AuthService.AuthException.class, () -> auth.handleInitialLoginResponse(response(200, body)));
        assertFalse(auth.isAuthenticated());
        HttpCookie cookie = new HttpCookie("refresh_token", "test-refresh");
        cookie.setPath("/api/auth");
        auth.getCookieManager().getCookieStore().add(BackendConfig.uri("/api/auth/"), cookie);
        assertFalse(auth.handleInitialLoginResponse(response(200, body)).mfaRequired());
        assertTrue(auth.isAuthenticated());
        assertEquals("test-refresh", store.value);
    }

    @Test void loginErrorNeverEchoesResponseBody() {
        var error = assertThrows(AuthService.AuthException.class,
                () -> auth.handleInitialLoginResponse(response(500, "private-value")));
        assertFalse(error.getMessage().contains("private-value"));
    }

    @Test void rejectedMfaDoesNotActivateSessionAndSuccessfulMfaConsumesChallenge() {
        auth.handleInitialLoginResponse(response(200, challenge(Instant.now().plusSeconds(180))));
        assertThrows(AuthService.AuthException.class, () -> auth.handleMfaResponse(response(401, "private-value")));
        assertFalse(auth.isAuthenticated());
        assertNull(store.value);
        HttpCookie cookie = new HttpCookie("refresh_token", "mfa-refresh");
        cookie.setPath("/api/auth");
        auth.getCookieManager().getCookieStore().add(BackendConfig.uri("/api/auth/"), cookie);
        assertEquals("mfa-access", auth.handleMfaResponse(response(200,
                "{\"accessToken\":\"mfa-access\",\"userId\":1,\"username\":\"alice\","
                + "\"publicUuid\":\"8c98baef-9c78-45d3-8797-b27e9786fa26\"}")));
        assertTrue(auth.isAuthenticated());
        assertEquals("mfa-refresh", store.value);
        assertTrue(auth.completeMfa("012345").isCompletedExceptionally());
    }

    private String challenge(Instant expiry) {
        return "{\"mfaRequired\":true,\"challengeToken\":\"private-value\",\"expiresAt\":\"" + expiry + "\"}";
    }

    private static HttpResponse<String> response(int status, String body) {
        return new HttpResponse<>() {
            public int statusCode() { return status; }
            public String body() { return body; }
            public HttpRequest request() { return HttpRequest.newBuilder(uri()).build(); }
            public Optional<HttpResponse<String>> previousResponse() { return Optional.empty(); }
            public HttpHeaders headers() { return HttpHeaders.of(Map.of(), (a,b) -> true); }
            public Optional<SSLSession> sslSession() { return Optional.empty(); }
            public URI uri() { return BackendConfig.uri("/api/auth/login"); }
            public HttpClient.Version version() { return HttpClient.Version.HTTP_1_1; }
        };
    }

    private static class MemoryStore implements RefreshTokenStore {
        String value;
        public void save(String token) { value = token; }
        public Optional<String> load() { return Optional.ofNullable(value); }
        public void delete() { value = null; }
    }
}
