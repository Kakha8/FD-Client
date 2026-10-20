package kakha.kudava.fdclient.service;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

/** Resolves the File Drive backend without hard-coding a deployment host. */
public final class BackendConfig {
    public static final String BASE_URL_ENV = "FDCLIENT_API_BASE_URL";
    public static final String WEBAUTHN_ORIGIN_ENV = "FDCLIENT_WEBAUTHN_ORIGIN";
    static final String DEFAULT_BASE_URL =
            "http://file-drive-preview-1837123084.eu-central-1.elb.amazonaws.com";
    private static final String AWS_PREVIEW_HOST =
            "file-drive-preview-1837123084.eu-central-1.elb.amazonaws.com";
    private static final URI BASE_URI = resolveBaseUri(
            configuredValue(System.getenv(), Path.of(".env"))
    );

    private BackendConfig() {}

    public static URI uri(String absolutePath) {
        if (absolutePath == null || !absolutePath.startsWith("/")) {
            throw new IllegalArgumentException("Backend path must start with '/'.");
        }
        return URI.create(BASE_URI + absolutePath);
    }

    /** Must match one of the backend's configured WebAuthn origins exactly. */
    public static String webAuthnOrigin() {
        String configured = configuredValue(System.getenv(), Path.of(".env"), WEBAUTHN_ORIGIN_ENV);
        if (configured == null || configured.isBlank()) configured = "http://localhost:5173";
        URI origin;
        try { origin = URI.create(configured.trim()); }
        catch (IllegalArgumentException error) { throw new IllegalStateException("Invalid " + WEBAUTHN_ORIGIN_ENV + "."); }
        boolean local = "localhost".equalsIgnoreCase(origin.getHost());
        if (!("https".equalsIgnoreCase(origin.getScheme()) || (local && "http".equalsIgnoreCase(origin.getScheme())))
                || origin.getHost() == null || origin.getUserInfo() != null || origin.getQuery() != null
                || origin.getFragment() != null || (origin.getPath() != null && !origin.getPath().isEmpty()))
            throw new IllegalStateException(WEBAUTHN_ORIGIN_ENV + " must be an exact HTTPS origin (HTTP localhost for development).");
        return origin.toString();
    }

    static URI resolveBaseUri(String configuredValue) {
        String value = configuredValue == null || configuredValue.isBlank()
                ? DEFAULT_BASE_URL
                : configuredValue.trim();
        while (value.endsWith("/")) value = value.substring(0, value.length() - 1);

        final URI uri;
        try {
            uri = URI.create(value);
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException(
                    BASE_URL_ENV + " is not a valid absolute URL.", exception);
        }
        boolean approvedPreviewHttp = "http".equalsIgnoreCase(uri.getScheme())
                && AWS_PREVIEW_HOST.equalsIgnoreCase(uri.getHost());
        if (!uri.isAbsolute()
                || !("https".equalsIgnoreCase(uri.getScheme()) || approvedPreviewHttp)
                || uri.getHost() == null
                || uri.getQuery() != null
                || uri.getFragment() != null
                || (uri.getPath() != null && !uri.getPath().isEmpty())) {
            throw new IllegalStateException(
                    BASE_URL_ENV + " must be an HTTPS origin, except for the current "
                            + "HTTP-only AWS preview origin.");
        }
        return uri;
    }

    static String configuredValue(Map<String, String> environment, Path envFile) {
        return configuredValue(environment, envFile, BASE_URL_ENV);
    }

    static String configuredValue(Map<String, String> environment, Path envFile, String key) {
        String processValue = environment.get(key);
        if (processValue != null && !processValue.isBlank()) {
            return processValue;
        }
        if (!Files.isRegularFile(envFile)) {
            return null;
        }

        final List<String> lines;
        try {
            lines = Files.readAllLines(envFile, StandardCharsets.UTF_8);
        } catch (Exception exception) {
            throw new IllegalStateException("Could not read " + envFile + ".", exception);
        }

        for (String originalLine : lines) {
            String line = originalLine.strip();
            if (line.startsWith("\uFEFF")) line = line.substring(1).strip();
            if (line.isEmpty() || line.startsWith("#")) continue;

            int separator = line.indexOf('=');
            if (separator < 1) continue;
            String name = line.substring(0, separator).trim();
            if (!key.equals(name)) continue;

            String value = line.substring(separator + 1).trim();
            if (value.length() >= 2
                    && ((value.startsWith("\"") && value.endsWith("\""))
                    || (value.startsWith("'") && value.endsWith("'")))) {
                value = value.substring(1, value.length() - 1);
            }
            return value;
        }
        return null;
    }
}
