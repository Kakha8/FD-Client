package kakha.kudava.fdclient.controller;

import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.stage.Window;
import kakha.kudava.fdclient.service.TotpSerialService;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.Objects;

/** Deliberately shows a plaintext seed for local hardware testing only. */
final class TotpDeviceTestWindow {
    private final TotpSerialService serial = new TotpSerialService();
    private final ExecutorService worker = Executors.newSingleThreadExecutor(r -> {
        Thread thread = new Thread(r, "totp-serial-test");
        thread.setDaemon(true);
        return thread;
    });
    private final ComboBox<TotpSerialService.Port> ports = new ComboBox<>();
    private final Button refresh = new Button("Refresh");
    private final Button read = new Button("Read device");
    private final TextField secret = new TextField();
    private final Label status = new Label();
    private boolean closed;
    private boolean busy;
    private Future<?> activeTask;

    static void show(Window owner) { new TotpDeviceTestWindow().open(owner); }

    private void open(Window owner) {
        Stage stage = new Stage();
        stage.initOwner(owner);
        stage.setTitle("ESP32 secret test — testing only");
        Label warning = new Label("TEST ONLY: displays the secret in plaintext. Anyone with it can clone your authenticator. "
                + "Nothing is saved or sent to the backend.");
        warning.setWrapText(true);
        Label help = new Label("Connect your ESP32 and close Arduino Serial Monitor. Select its port before reading.");
        help.setWrapText(true);
        ports.setPrefWidth(360);
        ports.setPromptText("Select COM port");
        ports.valueProperty().addListener((o, before, after) -> {
            secret.clear();
            read.setDisable(busy || after == null);
            if (!busy && !closed && !Objects.equals(before, after)) worker.submit(serial::close);
        });
        secret.setEditable(false);
        secret.setPromptText("The retrieved Base32 secret will appear here");
        secret.setStyle("-fx-font-family: monospace;");
        Button clear = new Button("Clear secret");
        clear.setOnAction(e -> secret.clear());
        refresh.setOnAction(e -> refreshPorts());
        read.setOnAction(e -> readDevice());
        status.setWrapText(true);
        VBox content = new VBox(12, warning, help, new HBox(8, ports, refresh), read,
                new Label("Retrieved secret (Base32)"), secret, clear, status);
        content.setPadding(new Insets(20));
        stage.setScene(new Scene(content, 570, 350));
        stage.setOnHidden(e -> {
            closed = true;
            secret.clear();
            if (activeTask != null) activeTask.cancel(true);
            // Queue cleanup after the interrupted read has released its connection.
            worker.submit(serial::close);
            worker.shutdown();
        });
        stage.show();
        refreshPorts();
    }

    private void setBusy(boolean value) {
        busy = value;
        ports.setDisable(value);
        refresh.setDisable(value);
        read.setDisable(value || ports.getValue() == null);
    }

    private void refreshPorts() {
        var previous = ports.getValue();
        secret.clear();
        setBusy(true);
        status.setText("Looking for serial ports...");
        activeTask = worker.submit(() -> {
            try {
                serial.close();
                var available = serial.listPorts();
                Platform.runLater(() -> {
                    if (closed) return;
                    ports.getItems().setAll(available);
                    ports.setValue(null);
                    if (available.size() == 1) ports.setValue(available.getFirst());
                    else if (previous != null) available.stream()
                            .filter(p -> p.name().equals(previous.name())).findFirst().ifPresent(ports::setValue);
                    setBusy(false);
                    status.setText(available.isEmpty() ? "No serial ports found. Connect the ESP32 and refresh."
                            : "Choose the ESP32 port, then click Read device. Port selection does not verify device identity.");
                });
            } catch (Exception | LinkageError error) {
                fail("Could not list serial ports. Check the USB driver and serial library installation.");
            }
        });
    }

    private void readDevice() {
        var selected = ports.getValue();
        if (selected == null) return;
        secret.clear();
        setBusy(true);
        status.setText("Reading " + selected.name() + " at 115200 baud; allowing time for device startup...");
        activeTask = worker.submit(() -> {
            try {
                String received = serial.readSecret(selected);
                Platform.runLater(() -> {
                    if (closed) return;
                    secret.setText(received);
                    status.setText("Secret received. Connection stays open for another read. Close this window to release the port.");
                    setBusy(false);
                });
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            } catch (Exception | LinkageError error) {
                fail("Could not read a valid secret. Close Serial Monitor, check the port and test sketch, then retry.");
            }
        });
    }

    private void fail(String message) {
        Platform.runLater(() -> {
            if (closed) return;
            secret.clear();
            status.setText(message);
            setBusy(false);
        });
    }
}
