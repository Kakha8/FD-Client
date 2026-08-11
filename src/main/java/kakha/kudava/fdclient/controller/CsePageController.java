package kakha.kudava.fdclient.controller;

import javafx.animation.KeyFrame;
import javafx.animation.Timeline;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.Node;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.MenuButton;
import javafx.scene.control.MenuItem;
import javafx.beans.property.ReadOnlyObjectWrapper;
import javafx.beans.property.ReadOnlyStringWrapper;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.ProgressIndicator;
import javafx.scene.control.TextField;
import javafx.scene.layout.AnchorPane;
import javafx.stage.FileChooser;
import javafx.stage.DirectoryChooser;
import javafx.stage.Window;
import javafx.util.Duration;
import kakha.kudava.fdclient.service.AuthService;
import kakha.kudava.fdclient.service.CseEncryptionService;
import kakha.kudava.fdclient.service.LockboxUploadService;
import kakha.kudava.fdclient.service.LockboxEnrollmentService;
import kakha.kudava.fdclient.service.LockboxDeviceIdentity;
import kakha.kudava.fdclient.service.LockboxMetadataService;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.net.InetAddress;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

public final class CsePageController {

    @FXML
    private Label lockboxStatusLabel;

    @FXML
    private Button activateLockboxBtn;

    @FXML
    private Button refreshLockboxBtn;

    @FXML
    private ProgressIndicator activationProgress;

    @FXML
    private AnchorPane lockboxContentPane;

    @FXML
    private TextField fileSelectField;

    @FXML
    private ProgressBar cseProgressBar;

    @FXML
    private TableView<LockboxMetadataService.PrivateFile> lockboxFileTable;

    @FXML
    private TableColumn<LockboxMetadataService.PrivateFile, String> nameColumn;

    @FXML
    private TableColumn<LockboxMetadataService.PrivateFile, Long> sizeColumn;

    @FXML
    private TableColumn<LockboxMetadataService.PrivateFile, String> locationColumn;

    @FXML
    private TableColumn<LockboxMetadataService.PrivateFile, Void> actionsColumn;

    @FXML
    private Button uploadBtn;

    @FXML
    private Button cancelUploadBtn;

    private final CseEncryptionService encryptionService =
            new CseEncryptionService();

    private final LockboxUploadService uploadService =
            new LockboxUploadService();

    private final LockboxEnrollmentService enrollmentService =
            new LockboxEnrollmentService();

    private final LockboxMetadataService metadataService =
            new LockboxMetadataService();

    private AuthService authService;
    private Path selectedFile;
    private CseEncryptionService.V3Artifacts encryptedArtifacts;
    private Timeline progressPoller;

    private CompletableFuture<
            LockboxUploadService.UploadResult
            > activeUpload;

    private boolean uploadCancelledByUser;

    private CompletableFuture<?> activeEnrollment;

    private LockboxEnrollmentService.EnrollmentChallenge
            pendingEnrollment;

    private boolean retryStatusCheck;

    public void setAuthService(AuthService authService) {
        this.authService = Objects.requireNonNull(
                authService,
                "authService"
        );

        checkLockboxStatus();
    }

    public AuthService getAuthService() {
        return authService;
    }

    @FXML
    private void initialize() {
        fileSelectField.setEditable(false);
        cseProgressBar.setProgress(0);

        hideUploadButton();
        hideCancelButton();

        lockboxFileTable.setPlaceholder(new Label("No Lockbox files."));
        nameColumn.setCellValueFactory(row -> new ReadOnlyStringWrapper(row.getValue().filename()));
        sizeColumn.setCellValueFactory(row -> new ReadOnlyObjectWrapper<>(row.getValue().plaintextSize()));
        sizeColumn.setCellFactory(column -> new TableCell<>() {
            @Override
            protected void updateItem(Long size, boolean empty) {
                super.updateItem(size, empty);
                if (empty || size == null) {
                    setText(null);
                } else {
                    setText(readableSize(size));
                }
            }
        });
        locationColumn.setCellValueFactory(row ->
                new ReadOnlyStringWrapper(row.getValue().location().displayName()));
        actionsColumn.setCellFactory(column -> new TableCell<>() {
            private final MenuButton menu = new MenuButton("⋮");
            private final MenuItem export = new MenuItem("Export");
            {
                menu.getItems().add(export);
                menu.setStyle("-fx-font-size: 17px; -fx-padding: 0 6 0 6;");
                export.setOnAction(event -> exportLocalArtifacts(getTableRow().getItem()));
            }

            @Override
            protected void updateItem(Void ignored, boolean empty) {
                super.updateItem(ignored, empty);
                LockboxMetadataService.PrivateFile file =
                        empty || getTableRow() == null ? null : getTableRow().getItem();
                setGraphic(file != null && file.localContainerPath() != null ? menu : null);
                setText(null);
            }
        });

        showLockboxState(
                LockboxUiState.LOADING,
                "Checking this device's Lockbox status..."
        );
    }

    @FXML
    private void onActivateLockbox() {
        if (activeEnrollment != null
                && !activeEnrollment.isDone()) {
            return;
        }

        if (retryStatusCheck) {
            checkLockboxStatus();
            return;
        }

        if (authService == null
                || !authService.isAuthenticated()) {
            showLockboxState(
                    LockboxUiState.ERROR,
                    "Your session is not authenticated. Log in again."
            );
            return;
        }

        showLockboxState(
                LockboxUiState.ACTIVATING,
                "Requesting a secure enrollment challenge..."
        );
        retryStatusCheck = false;

        CompletableFuture<
                LockboxEnrollmentService.EnrollmentChallenge
                > enrollment = enrollmentService.beginEnrollment(
                authService.getAccessToken()
        );

        activeEnrollment = enrollment;

        enrollment.whenComplete(
                (challenge, throwable) -> Platform.runLater(
                        () -> finishEnrollmentStart(
                                enrollment,
                                challenge,
                                throwable
                        )
                )
        );
    }

    private void checkLockboxStatus() {
        if (authService == null || !authService.isAuthenticated()) {
            retryStatusCheck = true;
            showLockboxState(
                    LockboxUiState.ERROR,
                    "Your session is not authenticated. Log in again."
            );
            return;
        }

        final UUID deviceId;
        try {
            deviceId = LockboxDeviceIdentity.loadOrCreate();
        } catch (RuntimeException error) {
            retryStatusCheck = true;
            showLockboxState(
                    LockboxUiState.ERROR,
                    messageOf(error, "Could not load the Lockbox device identity.")
            );
            return;
        }

        retryStatusCheck = false;
        showLockboxState(
                LockboxUiState.LOADING,
                "Checking this device's Lockbox status..."
        );

        CompletableFuture<LockboxEnrollmentService.LockboxStatus> request =
                enrollmentService.getStatus(authService.getAccessToken(), deviceId);
        activeEnrollment = request;
        request.whenComplete((status, error) -> Platform.runLater(() -> {
            if (activeEnrollment != request) {
                return;
            }
            activeEnrollment = null;
            if (error != null) {
                retryStatusCheck = true;
                showLockboxState(
                        LockboxUiState.ERROR,
                        messageOf(error, "Could not check Lockbox status.")
                );
                return;
            }
            if (!deviceId.equals(status.deviceId())) {
                retryStatusCheck = true;
                showLockboxState(
                        LockboxUiState.ERROR,
                        "The server returned a different Lockbox device ID."
                );
                return;
            }
            applyLockboxStatus(status);
        }));
    }

    private void applyLockboxStatus(
            LockboxEnrollmentService.LockboxStatus status
    ) {
        if (status.lockboxStatus()
                == LockboxEnrollmentService.AccountStatus.NOT_ENABLED) {
            showLockboxState(
                    LockboxUiState.NOT_ENABLED,
                    "Activate Lockbox to register this client."
            );
            return;
        }
        if (status.lockboxStatus()
                == LockboxEnrollmentService.AccountStatus.SUSPENDED) {
            showLockboxState(
                    LockboxUiState.BLOCKED,
                    "Lockbox is suspended for this account."
            );
            return;
        }

        switch (status.deviceStatus()) {
            case ACTIVE -> {
                showLockboxState(LockboxUiState.READY, "Lockbox is active on this device.");
                loadPrivateFileNames();
            }
            case NOT_REGISTERED -> showLockboxState(
                    LockboxUiState.BLOCKED,
                    "Lockbox is enabled, but this device is not registered."
            );
            case PENDING -> showLockboxState(
                    LockboxUiState.BLOCKED,
                    "Registration for this Lockbox device is pending."
            );
            case REVOKED -> showLockboxState(
                    LockboxUiState.BLOCKED,
                    "This Lockbox device has been revoked."
            );
        }
    }

    private void finishEnrollmentStart(
            CompletableFuture<
                    LockboxEnrollmentService.EnrollmentChallenge
                    > completed,
            LockboxEnrollmentService.EnrollmentChallenge challenge,
            Throwable throwable
    ) {
        if (activeEnrollment != completed) {
            return;
        }

        activeEnrollment = null;

        if (throwable != null) {
            showLockboxState(
                    LockboxUiState.ERROR,
                    messageOf(
                            throwable,
                            "Could not start Lockbox activation."
                    )
            );
            return;
        }

        pendingEnrollment = challenge;
        showLockboxState(LockboxUiState.ACTIVATING,
                "Generating device keys and signing the enrollment challenge...");

        UUID deviceId;
        try {
            deviceId = LockboxDeviceIdentity.loadOrCreate();
        } catch (RuntimeException error) {
            activeEnrollment = null;
            showLockboxState(LockboxUiState.ERROR,
                    messageOf(error, "Could not create the Lockbox device identity."));
            return;
        }
        String deviceName = localDeviceName();
        CompletableFuture<LockboxEnrollmentService.EnrollmentResult> completion =
                enrollmentService.completeEnrollment(
                        authService.getAccessToken(), challenge, deviceId, deviceName);
        activeEnrollment = completion;
        completion.whenComplete((result, error) -> Platform.runLater(() -> {
            if (activeEnrollment != completion) {
                return;
            }
            activeEnrollment = null;
            if (error != null) {
                showLockboxState(LockboxUiState.ERROR,
                        messageOf(error, "Could not complete Lockbox activation."));
                return;
            }
            pendingEnrollment = null;
            showLockboxState(LockboxUiState.READY,
                    "Lockbox is active on this device.");
            loadPrivateFileNames();
        }));
    }

    private String localDeviceName() {
        try {
            String name = InetAddress.getLocalHost().getHostName();
            return name == null || name.isBlank() ? "Windows device" : name;
        } catch (Exception ignored) {
            return "Windows device";
        }
    }

    private void showLockboxState(
            LockboxUiState state,
            String message
    ) {
        boolean busy = state == LockboxUiState.LOADING
                || state == LockboxUiState.ACTIVATING;

        activationProgress.setVisible(busy);
        activationProgress.setManaged(busy);

        boolean canActivate =
                state == LockboxUiState.NOT_ENABLED
                        || state == LockboxUiState.ERROR;

        activateLockboxBtn.setVisible(canActivate);
        activateLockboxBtn.setManaged(canActivate);
        activateLockboxBtn.setDisable(!canActivate);
        activateLockboxBtn.setText(
                state == LockboxUiState.ERROR
                        ? "Try Again"
                        : "Activate Lockbox"
        );

        boolean ready = state == LockboxUiState.READY;
        refreshLockboxBtn.setVisible(ready);
        refreshLockboxBtn.setManaged(ready);
        refreshLockboxBtn.setDisable(!ready);

        lockboxContentPane.setDisable(
                state != LockboxUiState.READY
        );

        lockboxStatusLabel.setText(message);
    }

    private enum LockboxUiState {
        LOADING,
        NOT_ENABLED,
        ACTIVATING,
        ENROLLMENT_PENDING,
        READY,
        BLOCKED,
        ERROR
    }

    @FXML
    private void onBrowse(ActionEvent event) {
        if (isUploadRunning()) {
            showError(
                    "Cancel the current upload before selecting "
                            + "another file."
            );
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Select file to encrypt");

        Window owner = ((Node) event.getSource())
                .getScene()
                .getWindow();

        File selected = fileChooser.showOpenDialog(owner);

        if (selected == null) {
            return;
        }

        selectedFile = selected.toPath();
        encryptedArtifacts = null;

        fileSelectField.setText(
                selectedFile.toAbsolutePath().toString()
        );

        cseProgressBar.setProgress(0);
        hideUploadButton();
        hideCancelButton();
    }

    @FXML
    private void onEncrypt(ActionEvent event) {
        if (isUploadRunning()) {
            showError(
                    "Cancel the current upload before encrypting "
                            + "another file."
            );
            return;
        }

        Button encryptButton = (Button) event.getSource();

        Path inputFile = resolveSelectedFile();

        if (inputFile == null) {
            showError("Select a file before encrypting.");
            return;
        }

        encryptedArtifacts = null;
        hideUploadButton();
        hideCancelButton();

        encryptButton.setDisable(true);
        cseProgressBar.setProgress(0);

        Task<CseEncryptionService.V3Artifacts> encryptionTask = new Task<>() {
            @Override
            protected CseEncryptionService.V3Artifacts call() {
                return encryptionService.encrypt(inputFile);
            }
        };

        startProgressPolling();

        encryptionTask.setOnSucceeded(workerEvent -> {
            stopProgressPolling();

            cseProgressBar.setProgress(1);
            encryptButton.setDisable(false);

            encryptedArtifacts = encryptionTask.getValue();
            showUploadButton();
            showEncryptionSuccess(encryptedArtifacts);
            loadPrivateFileNames();
        });

        encryptionTask.setOnFailed(workerEvent -> {
            stopProgressPolling();

            cseProgressBar.setProgress(0);
            encryptButton.setDisable(false);
            encryptedArtifacts = null;
            hideUploadButton();

            Throwable exception =
                    encryptionTask.getException();

            showError(
                    messageOf(
                            exception,
                            "The file could not be encrypted."
                    )
            );
        });

        Thread workerThread = new Thread(
                encryptionTask,
                "cse-encryption-worker"
        );

        workerThread.setDaemon(true);
        workerThread.start();
    }

    /**
     * Uploads to the current user's Lockbox root.
     *
     * A folder ID can be added later when the Lockbox folder browser
     * is connected to this page.
     */
    @FXML
    private void onUpload(ActionEvent event) {
        if (isUploadRunning()) {
            return;
        }

        if (encryptedArtifacts == null
                || !Files.isRegularFile(encryptedArtifacts.containerPath())
                || !Files.isRegularFile(encryptedArtifacts.manifestPath())
                || !Files.isRegularFile(encryptedArtifacts.signaturePath())) {
            showError(
                    "Encrypt a file before uploading it."
            );
            hideUploadButton();
            return;
        }

        if (authService == null
                || !authService.isAuthenticated()) {
            showError(
                    "Your session is not authenticated. "
                            + "Log in again."
            );
            return;
        }

        String accessToken =
                authService.getAccessToken();

        uploadCancelledByUser = false;

        uploadBtn.setDisable(true);
        hideUploadButton();
        showCancelButton();
        cseProgressBar.setProgress(0);

        CompletableFuture<
                LockboxUploadService.UploadResult
                > uploadFuture =
                uploadService.upload(
                        encryptedArtifacts,
                        null,
                        accessToken,
                        progress ->
                                Platform.runLater(
                                        () -> cseProgressBar
                                                .setProgress(progress)
                                )
                );

        activeUpload = uploadFuture;

        uploadFuture.whenComplete(
                (result, throwable) ->
                        Platform.runLater(
                                () -> finishUpload(
                                        uploadFuture,
                                        result,
                                        throwable
                                )
                        )
        );
    }

    @FXML
    private void onCancelUpload(ActionEvent event) {
        CompletableFuture<
                LockboxUploadService.UploadResult
                > upload = activeUpload;

        if (upload == null || upload.isDone()) {
            hideCancelButton();
            return;
        }

        uploadCancelledByUser = true;
        upload.cancel(true);
    }

    private void finishUpload(
            CompletableFuture<
                    LockboxUploadService.UploadResult
                    > completedFuture,
            LockboxUploadService.UploadResult result,
            Throwable throwable
    ) {
        /*
         * Ignore completion from an older request if another upload
         * has already replaced it.
         */
        if (activeUpload != completedFuture) {
            return;
        }

        activeUpload = null;
        hideCancelButton();

        if (throwable != null) {
            cseProgressBar.setProgress(0);
            showUploadButton();

            if (uploadCancelledByUser
                    || completedFuture.isCancelled()) {
                showUploadCancelled();
                return;
            }

            showError(
                    messageOf(
                            throwable,
                            "The encrypted file could not be uploaded."
                    )
            );
            return;
        }

        cseProgressBar.setProgress(1);
        hideUploadButton();

        showUploadSuccess(result);
        loadPrivateFileNames();
    }

    private boolean isUploadRunning() {
        return activeUpload != null
                && !activeUpload.isDone();
    }

    private Path resolveSelectedFile() {
        if (selectedFile != null) {
            return selectedFile;
        }

        String value = fileSelectField.getText();

        if (value == null || value.isBlank()) {
            return null;
        }

        try {
            return Path.of(value.trim());
        } catch (RuntimeException exception) {
            return null;
        }
    }

    private void loadPrivateFileNames() {
        if (authService == null || !authService.isAuthenticated()) return;
        refreshLockboxBtn.setDisable(true);
        lockboxFileTable.setDisable(true);
        lockboxFileTable.setPlaceholder(new Label("Loading Lockbox files..."));
        metadataService.list(authService.getAccessToken())
                .whenComplete((files, error) -> Platform.runLater(() -> {
                    lockboxFileTable.setDisable(false);
                    refreshLockboxBtn.setDisable(false);
                    if (error != null) {
                        lockboxFileTable.getItems().clear();
                        lockboxFileTable.setPlaceholder(new Label(
                                messageOf(error, "Could not load Lockbox filenames.")));
                        return;
                    }
                    lockboxFileTable.getItems().setAll(files);
                    lockboxFileTable.setPlaceholder(new Label("No Lockbox files."));
                }));
    }

    @FXML
    private void onRefreshLockbox() {
        loadPrivateFileNames();
    }

    private String readableSize(long bytes) {
        if (bytes < 0) return "unknown size";
        if (bytes < 1024) return bytes + " B";
        double value = bytes;
        String[] units = {"KB", "MB", "GB", "TB"};
        int unit = -1;
        do {
            value /= 1024.0;
            unit++;
        } while (value >= 1024.0 && unit < units.length - 1);
        return String.format(java.util.Locale.ROOT, "%.1f %s", value, units[unit]);
    }

    private void exportLocalArtifacts(LockboxMetadataService.PrivateFile file) {
        if (file == null || file.localContainerPath() == null) return;

        DirectoryChooser chooser = new DirectoryChooser();
        chooser.setTitle("Export Lockbox artifact set");
        File selectedDirectory = chooser.showDialog(lockboxFileTable.getScene().getWindow());
        if (selectedDirectory == null) return;

        Path destination = selectedDirectory.toPath().toAbsolutePath().normalize();
        Path sourceContainer = file.localContainerPath().toAbsolutePath().normalize();
        Path sourceDirectory = sourceContainer.getParent();
        String base = file.clientFileId().toString();
        List<Path> sources = List.of(
                sourceDirectory.resolve(base + ".fdcse"),
                sourceDirectory.resolve(base + ".fdmanifest"),
                sourceDirectory.resolve(base + ".fdsig")
        );
        List<Path> targets = sources.stream()
                .map(source -> destination.resolve(source.getFileName()))
                .toList();

        try {
            for (Path source : sources) {
                if (!Files.isRegularFile(source)) {
                    throw new IOException("The local artifact set is incomplete.");
                }
            }
            for (Path target : targets) {
                if (Files.exists(target)) {
                    throw new IOException("Export target already exists: " + target.getFileName());
                }
            }

            List<Path> created = new ArrayList<>();
            try {
                for (int index = 0; index < sources.size(); index++) {
                    Files.copy(sources.get(index), targets.get(index));
                    created.add(targets.get(index));
                }
            } catch (Exception error) {
                for (Path path : created) {
                    try {
                        Files.deleteIfExists(path);
                    } catch (IOException cleanupError) {
                        error.addSuppressed(cleanupError);
                    }
                }
                throw error;
            }

            Alert alert = new Alert(Alert.AlertType.INFORMATION);
            alert.setTitle("Export complete");
            alert.setHeaderText("The Lockbox artifact set was exported.");
            alert.setContentText(destination.toString());
            alert.showAndWait();
        } catch (Exception error) {
            showError(messageOf(error, "The Lockbox artifacts could not be exported."));
        }
    }

    private void startProgressPolling() {
        stopProgressPolling();

        progressPoller = new Timeline(
                new KeyFrame(
                        Duration.millis(100),
                        event -> {
                            double progress =
                                    encryptionService.progress();

                            cseProgressBar.setProgress(progress);
                        }
                )
        );

        progressPoller.setCycleCount(
                Timeline.INDEFINITE
        );

        progressPoller.play();
    }

    private void stopProgressPolling() {
        if (progressPoller == null) {
            return;
        }

        progressPoller.stop();
        progressPoller = null;
    }

    private void showUploadButton() {
        uploadBtn.setDisable(false);
        uploadBtn.setVisible(true);
        uploadBtn.setManaged(true);
    }

    private void hideUploadButton() {
        uploadBtn.setDisable(true);
        uploadBtn.setVisible(false);
        uploadBtn.setManaged(false);
    }

    private void showCancelButton() {
        cancelUploadBtn.setDisable(false);
        cancelUploadBtn.setVisible(true);
        cancelUploadBtn.setManaged(true);
    }

    private void hideCancelButton() {
        cancelUploadBtn.setDisable(true);
        cancelUploadBtn.setVisible(false);
        cancelUploadBtn.setManaged(false);
    }

    private String messageOf(
            Throwable throwable,
            String fallback
    ) {
        Throwable current = throwable;

        while (current instanceof CompletionException
                && current.getCause() != null) {
            current = current.getCause();
        }

        String message =
                current == null
                        ? null
                        : current.getMessage();

        return message == null || message.isBlank()
                ? fallback
                : message;
    }

    private void showEncryptionSuccess(CseEncryptionService.V3Artifacts artifacts) {
        Alert alert = new Alert(
                Alert.AlertType.INFORMATION
        );

        alert.setTitle("Encryption complete");
        alert.setHeaderText(
                "The file was encrypted successfully."
        );
        alert.setContentText(
                "Container:\n" + artifacts.containerPath()
                        + "\n\nManifest:\n" + artifacts.manifestPath()
                        + "\n\nSignature:\n" + artifacts.signaturePath()
                        + "\n\nThe complete artifact set is ready to upload."
        );

        alert.showAndWait();
    }

    private void showUploadSuccess(
            LockboxUploadService.UploadResult result
    ) {
        Alert alert = new Alert(
                Alert.AlertType.INFORMATION
        );

        alert.setTitle("Upload complete");
        alert.setHeaderText(
                "The encrypted file was uploaded to Lockbox."
        );
        alert.setContentText(
                "Server file ID: "
                        + result.id()
                        + "\nClient file ID: "
                        + result.clientFileId()
                        + "\nRevision: "
                        + result.revision()
                        + "\nContainer size: "
                        + result.containerSize()
                        + " bytes"
        );

        alert.showAndWait();
    }

    private void showUploadCancelled() {
        Alert alert = new Alert(
                Alert.AlertType.INFORMATION
        );

        alert.setTitle("Upload cancelled");
        alert.setHeaderText(
                "The Lockbox upload was cancelled."
        );
        alert.setContentText(
                "The encrypted local file was not deleted. "
                        + "You can retry the upload."
        );

        alert.showAndWait();
    }

    private void showError(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);

        alert.setTitle("Operation failed");
        alert.setHeaderText(
                "The requested operation could not be completed."
        );
        alert.setContentText(
                message == null || message.isBlank()
                        ? "An unknown error occurred."
                        : message
        );

        alert.showAndWait();
    }
}
