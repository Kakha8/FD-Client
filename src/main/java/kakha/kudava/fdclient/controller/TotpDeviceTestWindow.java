package kakha.kudava.fdclient.controller;

import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.control.PasswordField;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ScrollPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javafx.stage.Window;
import javafx.stage.Modality;
import kakha.kudava.fdclient.service.TotpSerialService;
import kakha.kudava.fdclient.service.AuthService;
import kakha.kudava.fdclient.service.TotpEnrollmentService;

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
    private AuthService auth;
    private Runnable onEnrolled;
    private Stage stage;
    private boolean httpBusy;
    private TotpEnrollmentService.Pending pending;
    private final TotpEnrollmentService enrollment = new TotpEnrollmentService();
    private final TextField deviceName = new TextField("My ESP32");
    private final PasswordField password = new PasswordField();
    private final CheckBox existingFactor = new CheckBox("My account already has MFA enabled");
    private final TextField existingId = new TextField();
    private final TextField existingCode = new TextField();
    private final TextField confirmationCode = new TextField();
    private final Button begin = new Button("Start enrollment");
    private final Button confirm = new Button("Confirm and enable MFA");
    private final Button restart = new Button("Start again");

    static void show(Window owner) { new TotpDeviceTestWindow().open(owner); }

    static void showEnrollment(Window owner, AuthService auth, Runnable onEnrolled) {
        TotpDeviceTestWindow window = new TotpDeviceTestWindow();
        window.auth = auth;
        window.onEnrolled = onEnrolled;
        window.open(owner);
    }

    private void open(Window owner) {
        stage = new Stage();
        stage.initOwner(owner);
        if (auth != null) stage.initModality(Modality.WINDOW_MODAL);
        stage.setTitle(auth == null ? "ESP32 secret test — testing only" : "Enroll ESP32 authenticator");
        Label warning = new Label("TEST ONLY: displays the secret in plaintext. Anyone with it can clone your authenticator. "
                + (auth == null ? "Nothing is saved or sent to the backend."
                : "Start enrollment sends it to your backend. Use a test account: recovery and device removal are not implemented."));
        warning.setWrapText(true);
        Label help = new Label("Connect your ESP32 and close Arduino Serial Monitor. Select its port before reading.");
        help.setWrapText(true);
        ports.setPrefWidth(360);
        ports.setPromptText("Select COM port");
        ports.valueProperty().addListener((o, before, after) -> {
            secret.clear();
            read.setDisable(busy || pending != null || after == null);
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
        if (auth != null) {
            password.setPromptText("Current account password");
            existingId.setPromptText("Existing active device ID");
            existingCode.setPromptText("Current code from existing device");
            confirmationCode.setPromptText("Six-digit code shown on the new ESP32");
            existingFactor.setOnAction(e -> setBusy(busy));
            begin.setOnAction(e -> beginEnrollment());
            confirm.setOnAction(e -> confirmEnrollment());
            restart.setOnAction(e -> {
                pending = null;
                secret.clear();
                confirmationCode.clear();
                setBusy(false);
                status.setText("Read the device again. Starting a new enrollment replaces the previous pending one.");
            });
            content.getChildren().addAll(new Label("Device name"), deviceName, password, existingFactor,
                    existingId, existingCode, begin, confirmationCode, new HBox(8, confirm, restart));
        }
        content.setPadding(new Insets(20));
        ScrollPane scroll = new ScrollPane(content);
        scroll.setFitToWidth(true);
        stage.setScene(new Scene(scroll, 620, auth == null ? 390 : 760));
        stage.setOnCloseRequest(e -> { if (httpBusy) e.consume(); });
        stage.setOnHidden(e -> {
            closed = true;
            secret.clear();
            password.clear();
            existingCode.clear();
            confirmationCode.clear();
            pending = null;
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
        ports.setDisable(value || pending != null);
        refresh.setDisable(value || pending != null);
        read.setDisable(value || pending != null || ports.getValue() == null);
        begin.setDisable(value || pending != null);
        confirm.setDisable(value || pending == null);
        restart.setDisable(value || pending == null);
        deviceName.setDisable(value || pending != null);
        password.setDisable(value || pending != null);
        existingFactor.setDisable(value || pending != null);
        existingId.setDisable(value || pending != null || !existingFactor.isSelected());
        existingCode.setDisable(value || pending != null || !existingFactor.isSelected());
        confirmationCode.setDisable(value || pending == null);
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

    private void beginEnrollment() {
        Long id = null;
        if (existingFactor.isSelected()) {
            try { id = Long.valueOf(existingId.getText().trim()); }
            catch (NumberFormatException ignored) { status.setText("Enter the numeric ID of your existing authenticator."); return; }
        }
        httpBusy = true;
        setBusy(true);
        status.setText("Creating pending enrollment...");
        var request = enrollment.begin(auth.getAccessToken(), deviceName.getText(), secret.getText(),
                password.getText(), id, existingCode.getText().trim());
        password.clear();
        existingCode.clear();
        request.whenComplete((result, error) -> Platform.runLater(() -> {
            httpBusy = false;
            if (closed) return;
            if (error != null) { status.setText(enrollmentError(error)); setBusy(false); return; }
            pending = result;
            secret.clear();
            worker.submit(serial::close);
            status.setText("Pending device " + result.deviceId() + ". Enter its displayed code before "
                    + result.expiresAt() + ". Confirmation enables MFA and returns you to login.");
            setBusy(false);
            confirmationCode.requestFocus();
        }));
    }

    private void confirmEnrollment() {
        if (pending == null) return;
        httpBusy = true;
        setBusy(true);
        status.setText("Confirming enrollment...");
        var request = enrollment.confirm(auth.getAccessToken(), pending, confirmationCode.getText().trim());
        confirmationCode.clear();
        request.whenComplete((result, error) -> Platform.runLater(() -> {
            httpBusy = false;
            if (closed) return;
            if (error != null) { status.setText(enrollmentError(error)); setBusy(false); return; }
            javafx.scene.control.Alert done = new javafx.scene.control.Alert(javafx.scene.control.Alert.AlertType.INFORMATION);
            done.initOwner(stage);
            done.setHeaderText("ESP32 enrolled — device ID " + pending.deviceId());
            done.setContentText("Keep this device ID for enrolling additional authenticators. You will now sign in again. "
                    + "Wait for a new code: the confirmation code has already been used. Recovery is not implemented.");
            done.showAndWait();
            stage.close();
            onEnrolled.run();
        }));
    }

    private String enrollmentError(Throwable error) {
        while (error instanceof java.util.concurrent.CompletionException && error.getCause() != null) error = error.getCause();
        if (error instanceof TotpEnrollmentService.EnrollmentException) return error.getMessage();
        return "No reliable server response. If confirming, MFA may already be enabled; try signing in with your ESP32. "
                + "Otherwise check the connection and start again.";
    }
}
