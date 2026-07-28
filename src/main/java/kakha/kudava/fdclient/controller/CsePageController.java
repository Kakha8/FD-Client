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
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Window;
import javafx.util.Duration;
import kakha.kudava.fdclient.service.AuthService;
import kakha.kudava.fdclient.service.CseEncryptionService;
import kakha.kudava.fdclient.service.LockboxUploadService;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

public final class CsePageController {

    @FXML
    private TextField fileSelectField;

    @FXML
    private ProgressBar cseProgressBar;

    @FXML
    private Button uploadBtn;

    @FXML
    private Button cancelUploadBtn;

    private final CseEncryptionService encryptionService =
            new CseEncryptionService();

    private final LockboxUploadService uploadService =
            new LockboxUploadService();

    private AuthService authService;
    private Path selectedFile;
    private Path encryptedFile;
    private Timeline progressPoller;

    private CompletableFuture<
            LockboxUploadService.UploadResult
            > activeUpload;

    private boolean uploadCancelledByUser;

    public void setAuthService(AuthService authService) {
        this.authService = Objects.requireNonNull(
                authService,
                "authService"
        );
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
        encryptedFile = null;

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

        encryptedFile = null;
        hideUploadButton();
        hideCancelButton();

        encryptButton.setDisable(true);
        cseProgressBar.setProgress(0);

        Task<Path> encryptionTask = new Task<>() {
            @Override
            protected Path call() {
                return encryptionService.encrypt(inputFile);
            }
        };

        startProgressPolling();

        encryptionTask.setOnSucceeded(workerEvent -> {
            stopProgressPolling();

            cseProgressBar.setProgress(1);
            encryptButton.setDisable(false);

            encryptedFile = encryptionTask.getValue();
            showUploadButton();

            showEncryptionSuccess(encryptedFile);
        });

        encryptionTask.setOnFailed(workerEvent -> {
            stopProgressPolling();

            cseProgressBar.setProgress(0);
            encryptButton.setDisable(false);
            encryptedFile = null;
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

        if (encryptedFile == null
                || !Files.isRegularFile(encryptedFile)) {
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
                        encryptedFile,
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

    private void showEncryptionSuccess(Path outputFile) {
        Alert alert = new Alert(
                Alert.AlertType.INFORMATION
        );

        alert.setTitle("Encryption complete");
        alert.setHeaderText(
                "The file was encrypted successfully."
        );
        alert.setContentText(
                "Encrypted file:\n"
                        + outputFile.toAbsolutePath()
                        + "\n\nThe Upload button is now available."
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
                        + "\nCiphertext size: "
                        + result.ciphertextSize()
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