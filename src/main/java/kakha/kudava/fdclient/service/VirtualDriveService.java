package kakha.kudava.fdclient.service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/** Owns the SSE filesystem helper; it is independent of CSE cryptography. */
public final class VirtualDriveService {
    private static final VirtualDriveService INSTANCE = new VirtualDriveService();

    private Process process;
    private CompletableFuture<Integer> pendingUpdate;
    private CompletableFuture<Integer> listingFuture;
    private AuthService refreshAuth;
    private long generation;
    private CompletableFuture<String> mountFuture;
    private SseTransferService transferService;

    private VirtualDriveService() {
        Runtime.getRuntime().addShutdownHook(new Thread(this::unmount, "fd-drive-shutdown"));
    }

    public static VirtualDriveService getInstance() {
        return INSTANCE;
    }

    public synchronized CompletableFuture<String> mount() {
        if (mountFuture != null && (!mountFuture.isDone()
                || (process != null && process.isAlive()))) {
            return mountFuture;
        }
        long request = ++generation;
        mountFuture = CompletableFuture.supplyAsync(() -> start(request));
        return mountFuture;
    }

    private String start(long request) {
        Process started = null;
        try {
            Path executable = findExecutable();
            Path staging = Files.createTempDirectory("fd-drive-");
            SseTransferService transfers = new SseTransferService(staging);
            synchronized (this) {
                if (generation != request) throw new CancellationException();
                ProcessBuilder builder = new ProcessBuilder(executable.toString()).redirectErrorStream(true);
                builder.environment().put("FD_DRIVE_STAGING", staging.toString());
                Path icon = Path.of("native-drive", "fd-client.ico").toAbsolutePath().normalize();
                if (Files.isRegularFile(icon)) {
                    builder.environment().put("FD_CLIENT_ICON", icon.toString());
                }
                started = builder.start();
                process = started;
                transferService = transfers;
            }
            Process child = started;
            BufferedReader output = new BufferedReader(new InputStreamReader(
                    child.getInputStream(), StandardCharsets.UTF_8));
            CompletableFuture<String> ready = CompletableFuture.supplyAsync(() -> {
                try {
                    return output.readLine();
                } catch (IOException e) {
                    throw new IllegalStateException("Could not read the drive helper response.", e);
                }
            });
            String drive = parseMountResponse(ready.get(15, TimeUnit.SECONDS));
            synchronized (this) {
                if (generation != request || process != child || !child.isAlive()) {
                    throw new CancellationException("Drive mounting was cancelled.");
                }
                
            }
            Thread reader = new Thread(() -> readEvents(child, output, transfers, request), "fd-drive-events");
            reader.setDaemon(true);
            reader.start();
            child.onExit().thenRun(() -> {
                transfers.cleanDownloads();
                synchronized (this) {
                    if (process == child) process = null;
                }
            });
            return drive;
        } catch (Exception error) {
            if (started != null) stopProcess(started);
            synchronized (this) {
                if (process == started) process = null;
            }
            if (error instanceof CancellationException cancelled) throw cancelled;
            throw new IllegalStateException("SSE drive could not mount: "
                    + (error.getMessage() == null ? error.getClass().getSimpleName() : error.getMessage()), error);
        }
    }

    /** Coalesces simultaneous Explorer refreshes into one backend traversal. */
    public synchronized CompletableFuture<Integer> loadListing(AuthService auth) {
        refreshAuth = auth;
        if (listingFuture != null && !listingFuture.isDone()) return listingFuture;
        CompletableFuture<String> mounted = mount();
        long request = generation;
        listingFuture = mounted.thenCompose(drive ->
                CompletableFuture.supplyAsync(() -> refreshSnapshot(auth, request)));
        return listingFuture;
    }

    private int refreshSnapshot(AuthService auth, long request) {
        SseTransferService transfers;
        synchronized (this) { transfers = transferService; }
        if (transfers == null) throw new CancellationException("Drive unmounted.");
        // Prevent an older listing from hiding a just-created folder/file.
        synchronized (transfers) { return refreshSnapshotLocked(auth, request); }
    }

    private int refreshSnapshotLocked(AuthService auth, long request) {
        Process child;
        synchronized (this) { child = process; }
        CompletableFuture<Integer> acknowledgement = new CompletableFuture<>();
        boolean sent = false;
        try {
            long account = auth.getUserId();
            String snapshot = new SseMetadataService().snapshot(auth);
            synchronized (this) {
                if (child == null || process != child || generation != request
                        || !auth.isAuthenticated() || auth.getUserId() != account) {
                    throw new CancellationException("SSE listing cancelled after logout.");
                }
                pendingUpdate = acknowledgement;
                child.getOutputStream().write((snapshot + "\n").getBytes(StandardCharsets.UTF_8));
                child.getOutputStream().flush();
                sent = true;
            }
            return acknowledgement.get(10, TimeUnit.SECONDS);
        } catch (Exception error) {
            synchronized (this) {
                if (process == child && generation == request && child != null) {
                    if (sent) {
                        // Do not allow a late ACK to acknowledge a later refresh.
                        unmount();
                    } else {
                        try {
                            child.getOutputStream().write("REFRESH_FAILED\n".getBytes(StandardCharsets.UTF_8));
                            child.getOutputStream().flush();
                        } catch (IOException ignored) { }
                    }
                }
                if (pendingUpdate == acknowledgement) pendingUpdate = null;
            }
            throw new IllegalStateException("Could not refresh SSE listing: " + error.getMessage(), error);
        }
    }

    /** Sole reader after the mount handshake: ACKs and refresh requests share stdout. */
    private void readEvents(Process child, BufferedReader output, SseTransferService transfers, long request) {
        try (output) {
            String line;
            while ((line = output.readLine()) != null) {
                if (line.startsWith("TRANSFER ")) {
                    handleTransfer(child, transfers, request, line.substring(9));
                    continue;
                }
                AuthService auth = null;
                synchronized (this) {
                    if (process != child) return;
                    if (line.equals("REFRESH")) {
                        auth = refreshAuth;
                    } else if (pendingUpdate != null) {
                        CompletableFuture<Integer> update = pendingUpdate;
                        pendingUpdate = null;
                        if (line.matches("UPDATED [0-9]+")) {
                            update.complete(Integer.parseInt(line.substring(8)));
                        } else {
                            update.completeExceptionally(new IllegalStateException(line));
                        }
                    }
                }
                if (line.equals("REFRESH")) {
                    synchronized (this) {
                        // Logout must not race an old event into mounting a new helper.
                        if (process != child) return;
                        if (auth != null && auth.isAuthenticated()) {
                            loadListing(auth).exceptionally(error -> {
                                System.err.println(error.getMessage());
                                return null;
                            });
                        } else {
                            child.getOutputStream().write("REFRESH_FAILED\n".getBytes(StandardCharsets.UTF_8));
                            child.getOutputStream().flush();
                        }
                    }
                }
            }
        } catch (IOException error) {
            System.err.println("SSE drive connection closed: " + error.getMessage());
        } finally {
            synchronized (this) {
                if (process == child && pendingUpdate != null) {
                    pendingUpdate.completeExceptionally(new IllegalStateException("SSE helper exited."));
                    pendingUpdate = null;
                }
            }
        }
    }

    private void handleTransfer(Process child, SseTransferService transfers, long request, String message) {
        final AuthService auth;
        final long account;
        final String token;
        synchronized (this) {
            if (process != child || generation != request) return;
            auth = refreshAuth;
            account = auth == null ? -1 : auth.getUserId();
            token = auth == null ? "" : auth.getAccessToken();
        }
        // The pipe reader must remain available for snapshot ACKs while HTTP is running.
        CompletableFuture.runAsync(() -> {
            synchronized (transfers) {
                var json = new com.fasterxml.jackson.databind.ObjectMapper();
                com.fasterxml.jackson.databind.JsonNode command;
                try { command = json.readTree(message); }
                catch (Exception error) { return; }
                com.fasterxml.jackson.databind.node.ObjectNode response;
                try {
                    response = transfers.execute(command, token, () -> {
                        synchronized (this) {
                            return process == child && generation == request && auth != null
                                    && auth.isAuthenticated() && auth.getUserId() == account;
                        }
                    });
                } catch (Exception error) {
                    response = json.createObjectNode().put("ok", false);
                    String detail = "SSE drive transfer failed: " + error.getMessage();
                    if (command.path("op").asText().startsWith("upload")) {
                        try { detail += "\nYour local copy is retained at:\n" + transfers.uploadPath(command.path("file").asText()); }
                        catch (IllegalArgumentException ignored) { }
                    }
                    if (command.path("op").asText().startsWith("upload") || command.path("op").asText().equals("delete")) {
                        if (command.path("op").asText().equals("delete")) {
                            detail += "\nItem: " + command.path("path").asText()
                                    + "\nRefresh the drive to check its server status before retrying.";
                        }
                        String notice = detail;
                        try {
                            javafx.application.Platform.runLater(() -> {
                                var alert = new javafx.scene.control.Alert(javafx.scene.control.Alert.AlertType.ERROR);
                                alert.setTitle("SSE drive operation failed");
                                alert.setHeaderText("The operation could not be completed.");
                                alert.setContentText(notice);
                                alert.show();
                            });
                        } catch (IllegalStateException ignored) { }
                    }
                    System.err.println(detail);
                }
                response.put("request", command.path("request").asLong());
                synchronized (this) {
                    if (process != child || generation != request) {
                        transfers.cleanDownloads();
                        return;
                    }
                    try {
                        child.getOutputStream().write(("TRANSFER " + response + "\n").getBytes(StandardCharsets.UTF_8));
                        child.getOutputStream().flush();
                    } catch (IOException error) { System.err.println("Could not acknowledge SSE transfer."); }
                }
            }
        });
    }

    /** Non-blocking. Closing stdin asks the helper to unmount, with a kill fallback. */
    public synchronized void unmount() {
        ++generation;
        Process current = process;
        process = null;
        mountFuture = null;
        listingFuture = null;
        refreshAuth = null;
        transferService = null;
        if (pendingUpdate != null) {
            pendingUpdate.completeExceptionally(new CancellationException("Drive unmounted."));
            pendingUpdate = null;
        }
        if (current != null) stopProcess(current);
    }

    private static void stopProcess(Process child) {
        try {
            child.getOutputStream().close();
        } catch (IOException ignored) {
            child.destroy();
        }
        child.onExit().orTimeout(3, TimeUnit.SECONDS).exceptionally(error -> {
            child.destroyForcibly();
            return child;
        });
    }

    static String parseMountResponse(String response) {
        if (response != null && response.matches("MOUNTED [D-Z]:")) {
            return response.substring("MOUNTED ".length());
        }
        throw new IllegalStateException(response == null
                ? "The native helper exited before mounting. Check that WinFsp is installed."
                : response);
    }

    private static Path findExecutable() {
        for (String location : new String[]{
                "native-drive/target/release/fd-virtual-drive.exe",
                "native-drive/target/debug/fd-virtual-drive.exe"
        }) {
            Path candidate = Path.of(location).toAbsolutePath().normalize();
            if (Files.isRegularFile(candidate)) return candidate;
        }
        throw new IllegalStateException(
                "Build the helper first: cargo build --manifest-path native-drive/Cargo.toml");
    }
}
