package kakha.kudava.fdclient.service;

import com.fazecast.jSerialComm.SerialPort;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

/** Test-only provisioning. Never logs or persists the device response. */
public final class TotpSerialService implements AutoCloseable {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final byte[] COMMAND = "ENROLL_EXPORT\n".getBytes(StandardCharsets.US_ASCII);
    private SerialPort connection;
    private String connectedName;

    public record Port(String name, String description) {
        @Override public String toString() { return name + " — " + description; }
    }

    public List<Port> listPorts() {
        return Arrays.stream(SerialPort.getCommPorts())
                .map(p -> new Port(p.getSystemPortName(), p.getDescriptivePortName()))
                .sorted(java.util.Comparator.comparing(Port::name)).toList();
    }

    private SerialPort connect(Port selected) throws IOException, InterruptedException {
        if (connection != null && selected.name().equals(connectedName) && connection.isOpen())
            return connection;
        close();
        SerialPort port = SerialPort.getCommPort(selected.name());
        port.setComPortParameters(115200, 8, SerialPort.ONE_STOP_BIT, SerialPort.NO_PARITY);
        port.setFlowControl(SerialPort.FLOW_CONTROL_DISABLED);
        port.setComPortTimeouts(SerialPort.TIMEOUT_READ_SEMI_BLOCKING
                | SerialPort.TIMEOUT_WRITE_BLOCKING, 200, 1000);
        // Keep RTS deasserted (it may drive EN/reset); assert DTR for USB CDC.
        // Set the desired state before opening rather than toggling both lines afterward.
        port.clearRTS();
        port.setDTR();
        if (!port.openPort()) {
            throw new IOException("Could not open port. Close Arduino Serial Monitor and try again.");
        }
        connection = port;
        connectedName = selected.name();
        // Only a new connection needs a boot grace period.
        Thread.sleep(2000);
        return port;
    }

    /** All connection operations run sequentially on the window's serial worker. */
    public synchronized String readSecret(Port selected) throws IOException, InterruptedException {
        byte[] buffer = new byte[256];
        StringBuilder line = new StringBuilder();
        try {
            SerialPort port = connect(selected);
            // Discard queued replies from a previous request, never show them as a new read.
            if (!port.flushIOBuffers()) throw new IOException("Could not clear serial buffers. Reconnect the device.");
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
            long nextSend = 0;
            boolean oversized = false;
            while (System.nanoTime() < deadline) {
                if (Thread.currentThread().isInterrupted()) throw new InterruptedException();
                if (System.nanoTime() >= nextSend) {
                    if (port.writeBytes(COMMAND, COMMAND.length) != COMMAND.length)
                        throw new IOException("Could not send command. Check the device connection.");
                    nextSend = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
                }
                int count = port.readBytes(buffer, buffer.length);
                if (count < 0) throw new IOException("Device disconnected or serial read failed.");
                for (int i = 0; i < count; i++) {
                    char c = (char) (buffer[i] & 0xff);
                    if (c == '\n') {
                        String secret = oversized ? null : parseSecret(line.toString());
                        line.setLength(0);
                        oversized = false;
                        if (secret != null) return secret;
                    } else if (c != '\r' && !oversized) {
                        if (line.length() < 1024) line.append(c);
                        else { oversized = true; line.setLength(0); }
                    }
                }
            }
            throw new IOException("No valid enrollment response. Check the selected port and test sketch.");
        } catch (IOException | InterruptedException | RuntimeException error) {
            close();
            throw error;
        } finally {
            Arrays.fill(buffer, (byte) 0);
            line.setLength(0);
        }
    }

    @Override
    public synchronized void close() {
        if (connection != null) {
            connection.closePort();
            connection = null;
            connectedName = null;
        }
    }

    static String parseSecret(String line) {
        if (line.length() > 1024 || !line.stripLeading().startsWith("{")) return null;
        try {
            JsonNode value = JSON.reader().with(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .readTree(line);
            if (!"totp-enrollment".equals(value.path("type").asText())
                    || !"SHA1".equals(value.path("algorithm").asText())
                    || !value.path("digits").isIntegralNumber() || value.path("digits").intValue() != 6
                    || !value.path("period").isIntegralNumber() || value.path("period").intValue() != 30
                    || !value.path("secretBase32").isTextual()) return null;
            String secret = value.path("secretBase32").textValue();
            return secret.matches("[A-Z2-7]{32}") ? secret : null;
        } catch (IOException ignored) {
            // Parser exception messages can contain the secret; never expose them.
            return null;
        }
    }
}
