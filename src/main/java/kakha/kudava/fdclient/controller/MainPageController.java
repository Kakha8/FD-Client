package kakha.kudava.fdclient.controller;

import javafx.event.ActionEvent;
import javafx.application.Platform;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.stage.Stage;
import javafx.stage.Window;
import kakha.kudava.fdclient.service.AuthService;
import kakha.kudava.fdclient.service.VirtualDriveService;

import java.io.IOException;
import java.util.Objects;

public class MainPageController {
    private AuthService authService;
    @FXML private Label driveStatusLabel;
    @FXML private Button openDriveButton;
    private String mountedDrive;

    public void setAuthService(AuthService authService) {
        this.authService = Objects.requireNonNull(
                authService,
                "authService"
        );
        initializeDrive();
    }

    public AuthService getAuthService() {
        return authService;
    }

    private void initializeDrive() {
        openDriveButton.setDisable(true);
        mountedDrive = null;
        driveStatusLabel.setText("Mounting SSE drive...");
        VirtualDriveService.getInstance().mount().whenComplete((drive, error) ->
                Platform.runLater(() -> {
                    if (error == null) {
                        mountedDrive = drive;
                        openDriveButton.setDisable(false);
                        driveStatusLabel.setText("FD Client (" + drive + ") — loading SSE listing...");
                        VirtualDriveService.getInstance().loadListing(authService)
                                .whenComplete((count, listingError) -> Platform.runLater(() -> {
                                    driveStatusLabel.setText(listingError == null
                                            ? "FD Client (" + drive + ") — listing only; refresh with F5 in Explorer"
                                            : "SSE listing failed: " + listingError.getMessage());
                                }));
                    } else {
                        Throwable cause = error.getCause() == null ? error : error.getCause();
                        driveStatusLabel.setText(cause.getMessage());
                    }
                }));
    }

    @FXML
    private void onTotpTest(ActionEvent event) {
        TotpDeviceTestWindow.show(((Node) event.getSource()).getScene().getWindow());
    }

    @FXML
    private void onOpenDrive() {
        if (mountedDrive == null) return;
        try {
            new ProcessBuilder("explorer.exe", mountedDrive + "\\").start();
        } catch (IOException error) {
            driveStatusLabel.setText("Could not open the mounted drive: " + error.getMessage());
        }
    }

    @FXML
    private void onLogout(ActionEvent event) {
        if (authService == null) {
            throw new IllegalStateException(
                    "No authentication session is available."
            );
        }

        try {
            VirtualDriveService.getInstance().unmount();
            authService.clearLocalSession();

            FXMLLoader loader = new FXMLLoader(
                    Objects.requireNonNull(
                            getClass().getResource(
                                    "/kakha/kudava/fdclient/login-page.fxml"
                            ),
                            "Could not find login-page.fxml"
                    )
            );
            Parent loginRoot = loader.load();

            Stage mainStage = (Stage) ((Node) event.getSource())
                    .getScene()
                    .getWindow();

            // Close authenticated secondary windows, such as the CSE page.
            for (Window window : Window.getWindows().toArray(Window[]::new)) {
                if (window != mainStage) {
                    window.hide();
                }
            }

            mainStage.getScene().setRoot(loginRoot);
            mainStage.setTitle("FD Client - Login");
            mainStage.sizeToScene();
            mainStage.centerOnScreen();
        } catch (IOException | RuntimeException exception) {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Logout failed");
            alert.setHeaderText("Could not log out safely.");
            alert.setContentText(exception.getMessage());
            alert.showAndWait();
        }
    }

    public void onCse(ActionEvent event) throws IOException {
        if (authService == null || !authService.isAuthenticated()) {
            throw new IllegalStateException(
                    "No authenticated session is available."
            );
        }

        FXMLLoader loader = new FXMLLoader(
                Objects.requireNonNull(
                        getClass().getResource(
                                "/kakha/kudava/fdclient/cse-page.fxml"
                        ),
                        "Could not find cse-page.fxml"
                )
        );

        Parent root = loader.load();

        CsePageController csePageController =
                loader.getController();

        /*
         * Pass the exact same AuthService instance that logged in.
         * It contains the in-memory access token.
         */
        csePageController.setAuthService(authService);

        Stage stage = new Stage();
        stage.setTitle("Lockbox Encryption");
        stage.setScene(new Scene(root));
        stage.show();
    }
}
