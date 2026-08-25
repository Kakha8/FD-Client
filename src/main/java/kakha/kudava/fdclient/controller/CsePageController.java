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
import javafx.scene.control.TextInputDialog;
import javafx.scene.control.ChoiceDialog;
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
import kakha.kudava.fdclient.service.LockboxInstallationIdentity;
import kakha.kudava.fdclient.service.LockboxMetadataService;
import kakha.kudava.fdclient.service.LockboxDownloadService;
import kakha.kudava.fdclient.service.LockboxDeletionService;
import kakha.kudava.fdclient.service.LockboxShareService;
import kakha.kudava.fdclient.service.LockboxDecryptExportService;
import kakha.kudava.fdclient.service.LockboxOwnDevice;
import kakha.kudava.fdclient.service.LockboxOwnDeviceService;

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

    private final LockboxDownloadService downloadService =
            new LockboxDownloadService();

    private final LockboxDeletionService deletionService =
            new LockboxDeletionService();

    private final LockboxDecryptExportService decryptExportService =
            new LockboxDecryptExportService();

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
                new ReadOnlyStringWrapper(row.getValue().locationDisplayName()));
        actionsColumn.setCellFactory(column -> new TableCell<>() {
            private final MenuButton menu = new MenuButton("⋮");
            private final MenuItem export = new MenuItem("Export");
            private final MenuItem decryptExport = new MenuItem("Decrypt and export…");
            private final MenuItem upload = new MenuItem("Upload");
            private final MenuItem download = new MenuItem("Download");
            private final MenuItem deleteLocal = new MenuItem("Delete locally");
            private final MenuItem deleteWeb = new MenuItem("Delete from web");
            private final MenuItem share = new MenuItem("Share…");
            private final MenuItem shareWithDevice = new MenuItem("Share with my device…");
            {
                menu.setStyle("-fx-font-size: 17px; -fx-padding: 0 6 0 6;");
                export.setOnAction(event -> exportLocalArtifacts(getTableRow().getItem()));
                decryptExport.setOnAction(event -> decryptAndExport(getTableRow().getItem(), menu));
                upload.setOnAction(event -> uploadLocalArtifacts(getTableRow().getItem(), menu));
                download.setOnAction(event -> downloadWebArtifacts(getTableRow().getItem(), menu));
                deleteLocal.setOnAction(event -> deleteLocalArtifacts(getTableRow().getItem(), menu));
                deleteWeb.setOnAction(event -> deleteWebArtifacts(getTableRow().getItem(), menu));
                share.setOnAction(event -> shareFile(getTableRow().getItem(), menu));
                shareWithDevice.setOnAction(event ->
                        shareFileWithOwnDevice(getTableRow().getItem(), menu));
            }

            @Override
            protected void updateItem(Void ignored, boolean empty) {
                super.updateItem(ignored, empty);
                LockboxMetadataService.PrivateFile file =
                        empty || getTableRow() == null ? null : getTableRow().getItem();
                menu.getItems().clear();
                if (file != null) {
                    menu.getItems().add(decryptExport);
                }
                if (file != null && file.localContainerPath() != null) {
                    menu.getItems().add(export);
                }
                if (file != null && file.accessKind() == LockboxMetadataService.AccessKind.OWNED
                        && file.localContainerPath() != null && file.serverId() == null) {
                    menu.getItems().add(upload);
                }
                if (file != null && file.serverId() != null && file.localContainerPath() == null) {
                    menu.getItems().add(download);
                }
                if (file != null && file.localContainerPath() != null) {
                    menu.getItems().add(deleteLocal);
                }
                if (file != null && file.accessKind() == LockboxMetadataService.AccessKind.OWNED
                        && file.serverId() != null) {
                    menu.getItems().add(deleteWeb);
                }
                if (file != null && file.accessKind() == LockboxMetadataService.AccessKind.OWNED
                        && file.serverId() != null && file.localContainerPath() != null) {
                    menu.getItems().add(0, share);
                    menu.getItems().add(1, shareWithDevice);
                }
                setGraphic(file != null && !menu.getItems().isEmpty() ? menu : null);
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
            refreshSessionAndCheckStatus();
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

        final UUID deviceId;
        final String installationHandle;
        final String deviceName;
        try {
            deviceId = LockboxDeviceIdentity.loadOrCreate();
            UUID installationId = LockboxInstallationIdentity.loadOrCreate();
            installationHandle = LockboxInstallationIdentity.deriveHandle(
                    installationId,
                    authService.getPublicUuid()
            );
            deviceName = localDeviceName();
        } catch (RuntimeException error) {
            showLockboxState(
                    LockboxUiState.ERROR,
                    messageOf(error, "Could not load the Lockbox installation identity.")
            );
            return;
        }

        CompletableFuture<
                LockboxEnrollmentService.EnrollmentChallenge
                > enrollment = enrollmentService.beginEnrollment(
                authService.getAccessToken(),
                deviceId,
                installationHandle,
                deviceName
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

    private void refreshSessionAndCheckStatus() {
        if (authService == null) {
            showLockboxState(
                    LockboxUiState.ERROR,
                    "No authentication session is available. Log in again."
            );
            return;
        }

        retryStatusCheck = false;
        showLockboxState(
                LockboxUiState.LOADING,
                "Refreshing your session..."
        );

        CompletableFuture<String> refresh = authService.refresh();
        activeEnrollment = refresh;
        refresh.whenComplete((accessToken, error) -> Platform.runLater(() -> {
            if (activeEnrollment != refresh) {
                return;
            }
            activeEnrollment = null;

            if (error != null) {
                retryStatusCheck = true;
                showLockboxState(
                        LockboxUiState.ERROR,
                        messageOf(error, "Could not refresh your session. Log in again.")
                );
                return;
            }

            checkLockboxStatus();
        }));
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
                    LockboxUiState.DEVICE_NOT_REGISTERED,
                    "Lockbox is enabled. Register this device to use it here."
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

        CompletableFuture<LockboxEnrollmentService.EnrollmentResult> completion =
                enrollmentService.completeEnrollment(
                        authService.getAccessToken(), challenge);
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
                        || state == LockboxUiState.DEVICE_NOT_REGISTERED
                        || state == LockboxUiState.ERROR;

        activateLockboxBtn.setVisible(canActivate);
        activateLockboxBtn.setManaged(canActivate);
        activateLockboxBtn.setDisable(!canActivate);
        activateLockboxBtn.setText(switch (state) {
            case ERROR -> "Try Again";
            case DEVICE_NOT_REGISTERED -> "Register Device";
            default -> "Activate Lockbox";
        });

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
        DEVICE_NOT_REGISTERED,
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
        loadPrivateFileNames(true);
    }

    private void loadPrivateFileNames(boolean allowSessionRefresh) {
        if (authService == null || !authService.isAuthenticated()) return;
        refreshLockboxBtn.setDisable(true);
        lockboxFileTable.setDisable(true);
        lockboxFileTable.setPlaceholder(new Label("Loading Lockbox files..."));
        final UUID deviceId;
        try {
            deviceId = LockboxDeviceIdentity.loadOrCreate();
        } catch (RuntimeException error) {
            refreshLockboxBtn.setDisable(false);
            lockboxFileTable.setDisable(false);
            lockboxFileTable.setPlaceholder(new Label(messageOf(
                    error, "Could not load this device identity.")));
            return;
        }
        metadataService.list(
                        authService.getAccessToken(),
                        authService.getPublicUuid(),
                        deviceId)
                .whenComplete((files, error) -> Platform.runLater(() -> {
                    if (error != null) {
                        if (allowSessionRefresh && causedBy(
                                error,
                                LockboxMetadataService.UnauthorizedException.class
                        )) {
                            lockboxFileTable.setPlaceholder(new Label("Refreshing your session..."));
                            authService.refresh().whenComplete((token, refreshError) ->
                                    Platform.runLater(() -> {
                                        if (refreshError != null) {
                                            lockboxFileTable.setDisable(false);
                                            refreshLockboxBtn.setDisable(false);
                                            lockboxFileTable.getItems().clear();
                                            lockboxFileTable.setPlaceholder(new Label(
                                                    messageOf(refreshError,
                                                            "Your session expired. Log in again.")));
                                            return;
                                        }
                                        loadPrivateFileNames(false);
                                    })
                            );
                            return;
                        }
                        lockboxFileTable.setDisable(false);
                        refreshLockboxBtn.setDisable(false);
                        lockboxFileTable.getItems().clear();
                        lockboxFileTable.setPlaceholder(new Label(
                                messageOf(error, "Could not load Lockbox filenames.")));
                        return;
                    }
                    lockboxFileTable.setDisable(false);
                    refreshLockboxBtn.setDisable(false);
                    lockboxFileTable.getItems().setAll(files);
                    lockboxFileTable.setPlaceholder(new Label("No Lockbox files."));
                }));
    }

    private boolean causedBy(
            Throwable error,
            Class<? extends Throwable> type
    ) {
        Throwable current = error;
        while (current != null) {
            if (type.isInstance(current)) return true;
            current = current.getCause();
        }
        return false;
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
        List<Path> sources = new ArrayList<>(List.of(
                sourceDirectory.resolve(base + ".fdcse"),
                sourceDirectory.resolve(base + ".fdmanifest"),
                sourceDirectory.resolve(base + ".fdsig")
        ));
        if (file.accessKind() == LockboxMetadataService.AccessKind.SHARED_WITH_ME) {
            sources.add(sourceDirectory.resolve(base + ".fdshare"));
        }
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

    private void decryptAndExport(
            LockboxMetadataService.PrivateFile file,
            MenuButton menu
    ) {
        if (file == null) return;
        if (file.localContainerPath() == null
                && (file.serverId() == null || authService == null || !authService.isAuthenticated())) {
            showError("Download the encrypted Lockbox file before decrypting it.");
            return;
        }

        FileChooser chooser = new FileChooser();
        chooser.setTitle("Decrypt and export Lockbox file");
        chooser.setInitialFileName(file.filename());
        File selected = chooser.showSaveDialog(lockboxFileTable.getScene().getWindow());
        if (selected == null) return;

        Path destination = selected.toPath().toAbsolutePath().normalize();
        if (Files.exists(destination)) {
            showError("The selected destination already exists. Choose a new filename.");
            return;
        }

        menu.setDisable(true);
        cseProgressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        decryptAndExport(file, destination, menu, true);
    }

    private void decryptAndExport(
            LockboxMetadataService.PrivateFile file,
            Path destination,
            MenuButton menu,
            boolean allowSessionRefresh
    ) {
        CompletableFuture<Void> operation;
        if (file.localContainerPath() != null) {
            operation = decryptExportService.decryptAndExport(file, destination);
        } else {
            operation = downloadService.download(
                            file,
                            authService.getAccessToken(),
                            LockboxDeviceIdentity.loadOrCreate())
                    .thenCompose(ignored -> {
                        Path localContainer = encryptionService.artifactDirectory()
                                .resolve(file.clientFileId() + ".fdcse");
                        return decryptExportService.decryptAndExport(
                                file.withLocalContainerPath(localContainer), destination);
                    });
        }
        operation
                .whenComplete((ignored, error) -> Platform.runLater(() -> {
                    if (error != null) {
                        if (allowSessionRefresh && causedBy(
                                error, LockboxDownloadService.UnauthorizedException.class)) {
                            authService.refresh().whenComplete((token, refreshError) ->
                                    Platform.runLater(() -> {
                                        if (refreshError != null) {
                                            menu.setDisable(false);
                                            cseProgressBar.setProgress(0);
                                            showError(messageOf(refreshError,
                                                    "Your session expired. Log in again."));
                                            return;
                                        }
                                        decryptAndExport(file, destination, menu, false);
                                    }));
                            return;
                        }
                        menu.setDisable(false);
                        cseProgressBar.setProgress(0);
                        showError(messageOf(error, "The Lockbox file could not be decrypted."));
                        return;
                    }
                    menu.setDisable(false);
                    cseProgressBar.setProgress(1);
                    loadPrivateFileNames();
                    Alert alert = new Alert(Alert.AlertType.INFORMATION);
                    alert.setTitle("Export complete");
                    alert.setHeaderText("The decrypted file was exported successfully.");
                    alert.setContentText(destination.toString());
                    Window owner = lockboxFileTable.getScene().getWindow();
                    if (owner != null) alert.initOwner(owner);
                    alert.showAndWait();
                }));
    }

    private void downloadWebArtifacts(
            LockboxMetadataService.PrivateFile file,
            MenuButton menu
    ) {
        downloadWebArtifacts(file, menu, true);
    }

    private void downloadWebArtifacts(
            LockboxMetadataService.PrivateFile file,
            MenuButton menu,
            boolean allowSessionRefresh
    ) {
        if (file == null || file.serverId() == null) return;
        if (authService == null || !authService.isAuthenticated()) {
            showError("Your session is not authenticated.");
            return;
        }

        menu.setDisable(true);
        cseProgressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        downloadService.download(
                        file,
                        authService.getAccessToken(),
                        LockboxDeviceIdentity.loadOrCreate())
                .whenComplete((ignored, error) -> Platform.runLater(() -> {
                    if (error != null) {
                        if (allowSessionRefresh && causedBy(
                                error,
                                LockboxDownloadService.UnauthorizedException.class
                        )) {
                            cseProgressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
                            authService.refresh().whenComplete((token, refreshError) ->
                                    Platform.runLater(() -> {
                                        if (refreshError != null) {
                                            menu.setDisable(false);
                                            cseProgressBar.setProgress(0);
                                            showError(messageOf(
                                                    refreshError,
                                                    "Your session expired. Log in again."
                                            ));
                                            return;
                                        }
                                        downloadWebArtifacts(file, menu, false);
                                    })
                            );
                            return;
                        }
                        menu.setDisable(false);
                        cseProgressBar.setProgress(0);
                        showError(messageOf(error, "The Lockbox file could not be downloaded."));
                        return;
                    }
                    menu.setDisable(false);
                    cseProgressBar.setProgress(1);
                    loadPrivateFileNames();
                    Alert alert = new Alert(Alert.AlertType.INFORMATION);
                    alert.setTitle("Download complete");
                    alert.setHeaderText("The encrypted Lockbox artifact set is now local.");
                    alert.setContentText(encryptionService.artifactDirectory().toString());
                    alert.showAndWait();
                }));
    }

    private void uploadLocalArtifacts(
            LockboxMetadataService.PrivateFile file,
            MenuButton menu
    ) {
        if (file == null || file.localContainerPath() == null || file.serverId() != null) return;
        if (isUploadRunning()) {
            showError("Another Lockbox upload is already running.");
            return;
        }
        if (authService == null || !authService.isAuthenticated()) {
            showError("Your session is not authenticated. Log in again.");
            return;
        }

        final CseEncryptionService.V3Artifacts artifacts;
        try {
            artifacts = encryptionService.loadLocalArtifacts(
                    file.clientFileId(),
                    file.localContainerPath()
            );
        } catch (RuntimeException error) {
            showError(messageOf(error, "The local Lockbox artifacts could not be loaded."));
            return;
        }

        uploadCancelledByUser = false;
        menu.setDisable(true);
        showCancelButton();
        cseProgressBar.setProgress(0);

        CompletableFuture<LockboxUploadService.UploadResult> uploadFuture =
                uploadService.upload(
                        artifacts,
                        null,
                        authService.getAccessToken(),
                        progress -> Platform.runLater(
                                () -> cseProgressBar.setProgress(progress)
                        )
                );
        activeUpload = uploadFuture;

        uploadFuture.whenComplete((result, error) -> Platform.runLater(() -> {
            menu.setDisable(false);
            if (activeUpload != uploadFuture) return;
            activeUpload = null;
            hideCancelButton();

            if (error != null) {
                cseProgressBar.setProgress(0);
                if (uploadCancelledByUser || uploadFuture.isCancelled()) {
                    showUploadCancelled();
                } else {
                    showError(messageOf(error, "The encrypted file could not be uploaded."));
                }
                return;
            }

            cseProgressBar.setProgress(1);
            loadPrivateFileNames();
            showUploadSuccess(result);
        }));
    }

    private void deleteLocalArtifacts(
            LockboxMetadataService.PrivateFile file,
            MenuButton menu
    ) {
        if (file == null || file.localContainerPath() == null) return;
        if (!confirmDeletion(
                "Delete local copy?",
                "Delete the local encrypted copy of " + file.filename() + "?",
                "This removes its container, manifest, and signature from this device."
        )) return;

        menu.setDisable(true);
        deletionService.deleteLocal(file)
                .whenComplete((ignored, error) -> Platform.runLater(() -> {
                    menu.setDisable(false);
                    if (error != null) {
                        showError(messageOf(error, "The local Lockbox file could not be deleted."));
                        return;
                    }
                    loadPrivateFileNames();
                }));
    }

    private void deleteWebArtifacts(
            LockboxMetadataService.PrivateFile file,
            MenuButton menu
    ) {
        if (file == null || file.serverId() == null) return;
        if (authService == null || !authService.isAuthenticated()) {
            showError("Your session is not authenticated.");
            return;
        }
        if (!confirmDeletion(
                "Delete web copy?",
                "Permanently delete the web copy of " + file.filename() + "?",
                "The encrypted container, manifest, and signature will be removed from the server."
        )) return;

        menu.setDisable(true);
        deletionService.deleteWeb(file.serverId(), authService.getAccessToken())
                .whenComplete((ignored, error) -> Platform.runLater(() -> {
                    menu.setDisable(false);
                    if (error != null) {
                        showError(messageOf(error, "The web Lockbox file could not be deleted."));
                        return;
                    }
                    loadPrivateFileNames();
                }));
    }

    private void shareFile(
            LockboxMetadataService.PrivateFile file,
            MenuButton menu
    ) {
        if (file == null || file.serverId() == null || file.localContainerPath() == null) return;
        if (authService == null || !authService.isAuthenticated()) {
            showError("Your session is not authenticated. Log in again.");
            return;
        }

        TextInputDialog dialog = new TextInputDialog();
        dialog.setTitle("Share Lockbox file");
        dialog.setHeaderText("Share " + file.filename());
        dialog.setContentText("Recipient username:");
        Window owner = lockboxFileTable.getScene().getWindow();
        if (owner != null) dialog.initOwner(owner);
        String username = dialog.showAndWait().map(String::trim).orElse("");
        if (username.isEmpty()) return;

        menu.setDisable(true);
        cseProgressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        new LockboxShareService(authService).share(file, username, 0)
                .whenComplete((result, error) -> Platform.runLater(() -> {
                    menu.setDisable(false);
                    cseProgressBar.setProgress(error == null ? 1 : 0);
                    if (error != null) {
                        showError(messageOf(error, "The Lockbox file could not be shared."));
                        return;
                    }
                    Alert alert = new Alert(Alert.AlertType.INFORMATION);
                    alert.setTitle("Share created");
                    alert.setHeaderText("The Lockbox file was shared successfully.");
                    alert.setContentText("Recipient: " + result.recipientUsername());
                    if (owner != null) alert.initOwner(owner);
                    alert.showAndWait();
                }));
    }

    private void shareFileWithOwnDevice(
            LockboxMetadataService.PrivateFile file,
            MenuButton menu
    ) {
        if (file == null || file.serverId() == null || file.localContainerPath() == null) return;
        if (authService == null || !authService.isAuthenticated()) {
            showError("Your session is not authenticated. Log in again.");
            return;
        }

        final UUID currentDeviceId;
        try {
            currentDeviceId = LockboxDeviceIdentity.loadOrCreate();
        } catch (RuntimeException error) {
            showError(messageOf(error, "Could not load this device identity."));
            return;
        }

        menu.setDisable(true);
        cseProgressBar.setProgress(ProgressBar.INDETERMINATE_PROGRESS);
        new LockboxOwnDeviceService(authService).listOtherDevices(currentDeviceId)
                .whenComplete((devices, listError) -> Platform.runLater(() -> {
                    if (listError != null) {
                        menu.setDisable(false);
                        cseProgressBar.setProgress(0);
                        showError(messageOf(listError, "Could not load your other devices."));
                        return;
                    }
                    if (devices.isEmpty()) {
                        menu.setDisable(false);
                        cseProgressBar.setProgress(0);
                        showError("No other active Lockbox devices are registered for this account.");
                        return;
                    }

                    ChoiceDialog<LockboxOwnDevice> dialog =
                            new ChoiceDialog<>(devices.getFirst(), devices);
                    dialog.setTitle("Share with my device");
                    dialog.setHeaderText("Share " + file.filename());
                    dialog.setContentText("Target device:");
                    Window owner = lockboxFileTable.getScene().getWindow();
                    if (owner != null) dialog.initOwner(owner);
                    LockboxOwnDevice target = dialog.showAndWait().orElse(null);
                    if (target == null) {
                        menu.setDisable(false);
                        cseProgressBar.setProgress(0);
                        return;
                    }

                    new LockboxShareService(authService)
                            .shareWithOwnDevice(file, target, 0)
                            .whenComplete((result, shareError) -> Platform.runLater(() -> {
                                menu.setDisable(false);
                                cseProgressBar.setProgress(shareError == null ? 1 : 0);
                                if (shareError != null) {
                                    showError(messageOf(
                                            shareError,
                                            "The Lockbox file could not be shared with that device."));
                                    return;
                                }
                                Alert alert = new Alert(Alert.AlertType.INFORMATION);
                                alert.setTitle("Device share created");
                                alert.setHeaderText("The Lockbox file was shared successfully.");
                                alert.setContentText("Target device: " + target.deviceName());
                                if (owner != null) alert.initOwner(owner);
                                alert.showAndWait();
                            }));
                }));
    }

    private boolean confirmDeletion(
            String title,
            String header,
            String content
    ) {
        Alert alert = new Alert(Alert.AlertType.CONFIRMATION);
        alert.setTitle(title);
        alert.setHeaderText(header);
        alert.setContentText(content);
        Window window = lockboxFileTable.getScene().getWindow();
        if (window != null) alert.initOwner(window);
        return alert.showAndWait()
                .filter(button -> button == javafx.scene.control.ButtonType.OK)
                .isPresent();
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
