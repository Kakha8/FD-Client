package kakha.kudava.fdclient.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class BackendConfigTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void blankConfigurationUsesLocalhost() {
        assertEquals(
                URI.create("https://localhost:8443"),
                BackendConfig.resolveBaseUri(" ")
        );
    }

    @Test
    void lanOriginIsAcceptedAndTrailingSlashIsRemoved() {
        assertEquals(
                URI.create("https://192.168.100.5:8443"),
                BackendConfig.resolveBaseUri("https://192.168.100.5:8443/")
        );
    }

    @Test
    void insecureOrPathBearingValuesAreRejected() {
        assertThrows(IllegalStateException.class,
                () -> BackendConfig.resolveBaseUri("http://192.168.100.5:8443"));
        assertThrows(IllegalStateException.class,
                () -> BackendConfig.resolveBaseUri("https://example.test/api"));
    }

    @Test
    void readsProjectDotEnvWhenProcessVariableIsMissing() throws Exception {
        Path envFile = temporaryDirectory.resolve(".env");
        Files.writeString(envFile, "# comment\nFDCLIENT_API_BASE_URL='https://192.168.100.5:8443'\n");

        assertEquals(
                "https://192.168.100.5:8443",
                BackendConfig.configuredValue(Map.of(), envFile)
        );
    }

    @Test
    void processEnvironmentOverridesDotEnv() throws Exception {
        Path envFile = temporaryDirectory.resolve(".env");
        Files.writeString(envFile, "FDCLIENT_API_BASE_URL=https://192.168.100.5:8443\n");

        assertEquals(
                "https://localhost:8443",
                BackendConfig.configuredValue(
                        Map.of(BackendConfig.BASE_URL_ENV, "https://localhost:8443"),
                        envFile
                )
        );
    }
}
