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
    private static final String DEFAULT_BASE_URL = "https://localhost:8443";
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
                    BASE_URL_ENV + " is not a valid absolute HTTPS URL.", exception);
        }
        if (!uri.isAbsolute()
                || !"https".equalsIgnoreCase(uri.getScheme())
                || uri.getHost() == null
                || uri.getQuery() != null
                || uri.getFragment() != null
                || (uri.getPath() != null && !uri.getPath().isEmpty())) {
            throw new IllegalStateException(
                    BASE_URL_ENV + " must be an HTTPS origin such as "
                            + "https://192.168.100.5:8443.");
        }
        return uri;
    }

    static String configuredValue(Map<String, String> environment, Path envFile) {
        String processValue = environment.get(BASE_URL_ENV);
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
            if (!BASE_URL_ENV.equals(name)) continue;

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
