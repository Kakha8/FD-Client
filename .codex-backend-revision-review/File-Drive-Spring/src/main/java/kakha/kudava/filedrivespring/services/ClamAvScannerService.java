package kakha.kudava.filedrivespring.services;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;

@Service
public class ClamAvScannerService {

    private final String host;
    private final int port;
    private final int timeoutMs;

    public ClamAvScannerService(
            @Value("${clamav.host}") String host,
            @Value("${clamav.port}") int port,
            @Value("${clamav.timeout-ms}") int timeoutMs
    ) {
        this.host = host;
        this.port = port;
        this.timeoutMs = timeoutMs;
    }

    public ScanResult scan(Path file) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);

            OutputStream out = socket.getOutputStream();
            InputStream socketIn = socket.getInputStream();

            // zINSTREAM asks clamd to scan streamed bytes.
            out.write("zINSTREAM\0".getBytes());

            try (InputStream fileIn = Files.newInputStream(file)) {
                byte[] buffer = new byte[8192];
                int read;

                while ((read = fileIn.read(buffer)) != -1) {
                    out.write(ByteBuffer.allocate(4).putInt(read).array());
                    out.write(buffer, 0, read);
                }
            }

            // zero-length chunk ends the stream
            out.write(new byte[]{0, 0, 0, 0});
            out.flush();

            String response = readResponse(socketIn);

            if (response.contains("FOUND")) {
                return ScanResult.infected(response);
            }

            if (response.contains("OK")) {
                return ScanResult.clean(response);
            }

            throw new IOException("Unexpected ClamAV response: " + response);
        }
    }

    private String readResponse(InputStream in) throws IOException {
        ByteArrayOutputStream response = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int read = in.read(buffer);

        if (read > 0) {
            response.write(buffer, 0, read);
        }

        return response.toString().trim();
    }

    public record ScanResult(boolean clean, String response) {
        public static ScanResult clean(String response) {
            return new ScanResult(true, response);
        }

        public static ScanResult infected(String response) {
            return new ScanResult(false, response);
        }
    }
}