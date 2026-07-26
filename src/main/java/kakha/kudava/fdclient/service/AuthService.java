package kakha.kudava.fdclient.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

public final class AuthService {

    private static final URI LOGIN_URI =
            URI.create("https://localhost:8443/api/auth/login");

    private final ObjectMapper objectMapper = new ObjectMapper();

    /*
     * The CookieManager captures the refresh_token cookie returned by
     * the Spring server.
     */
    private final CookieManager cookieManager =
            new CookieManager(null, CookiePolicy.ACCEPT_ALL);

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .cookieHandler(cookieManager)
            .build();

    private volatile String accessToken;

    public CompletableFuture<String> login(
            String username,
            String password
    ) {
        String requestBody;

        try {
            ObjectNode json = objectMapper.createObjectNode();
            json.put("username", username);
            json.put("password", password);

            requestBody = objectMapper.writeValueAsString(json);
        } catch (Exception exception) {
            return CompletableFuture.failedFuture(exception);
        }

        HttpRequest request = HttpRequest.newBuilder()
                .uri(LOGIN_URI)
                .timeout(Duration.ofSeconds(20))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        return httpClient.sendAsync(
                        request,
                        HttpResponse.BodyHandlers.ofString()
                )
                .thenApply(this::handleLoginResponse);
    }

    private String handleLoginResponse(
            HttpResponse<String> response
    ) {
        if (response.statusCode() == 200) {
            try {
                JsonNode json = objectMapper.readTree(response.body());

                String token = json.path("accessToken").asText();

                if (token.isBlank()) {
                    throw new AuthException(
                            "The server did not return an access token."
                    );
                }

                accessToken = token;
                return token;
            } catch (AuthException exception) {
                throw exception;
            } catch (Exception exception) {
                throw new CompletionException(
                        "Could not parse the login response.",
                        exception
                );
            }
        }

        if (response.statusCode() == 401
                || response.statusCode() == 403) {
            throw new AuthException(
                    "Incorrect username or password."
            );
        }

        throw new AuthException(
                "Login failed. Server returned HTTP "
                        + response.statusCode()
                        + ". Response: "
                        + response.body()
        );
    }

    public String getAccessToken() {
        return accessToken;
    }

    public CookieManager getCookieManager() {
        return cookieManager;
    }

    public static final class AuthException
            extends RuntimeException {

        public AuthException(String message) {
            super(message);
        }
    }
}