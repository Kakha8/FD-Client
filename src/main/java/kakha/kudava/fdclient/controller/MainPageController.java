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
import javafx.scene.layout.VBox;
import javafx.animation.Timeline;
import javafx.animation.KeyFrame;
import javafx.animation.KeyValue;
import javafx.animation.Interpolator;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.StackPane;
import javafx.util.Duration;
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
    @FXML private VBox sidebar;
    @FXML private javafx.scene.control.MenuButton userMenu;
    @FXML private Label userInitials;
    @FXML private Label accountInitials;
    @FXML private Label accountName;
    @FXML private VBox homeContent;
    @FXML private VBox sharedContent;
    private boolean sidebarExpanded = false;
    private Timeline sidebarAnimation;
    private String mountedDrive;

    @FXML
    private void initialize() {
        sidebar.getChildren().stream().filter(Button.class::isInstance).map(Button.class::cast).forEach(button -> {
            StackPane icon = new StackPane(button.getGraphic());
            icon.setMinSize(22, 22);
            icon.setPrefSize(22, 22);
            icon.setMaxSize(22, 22);
            button.setGraphic(icon);
            button.setMaxWidth(Double.MAX_VALUE);
            button.setTooltip(new Tooltip(button.getAccessibleText()));
            if (button.getStyleClass().contains("nav-button")) button.setText("");
        });
    }

    @FXML
    private void onToggleSidebar() {
        sidebarExpanded = !sidebarExpanded;
        double target = sidebarExpanded ? 220 : 64;
        if (sidebarAnimation != null) sidebarAnimation.stop();
        sidebarAnimation = new Timeline(new KeyFrame(Duration.millis(200),
                new KeyValue(sidebar.prefWidthProperty(), target, Interpolator.EASE_BOTH)));
        sidebarAnimation.play();
        sidebar.getStyleClass().setAll("sidebar", sidebarExpanded ? "expanded" : "collapsed");
        sidebar.lookupAll(".nav-button").forEach(node -> ((Button) node).setText(sidebarExpanded ? ((Button) node).getAccessibleText() : ""));
    }

    @FXML private void onHome() { showSharedContent(false); }

    @FXML private void onSharedWithMe() { showSharedContent(true); }

    private void showSharedContent(boolean shared) {
        homeContent.setVisible(!shared);
        homeContent.setManaged(!shared);
        sharedContent.setVisible(shared);
        sharedContent.setManaged(shared);
    }

    @FXML
    private void onNotifications() {
        new Alert(Alert.AlertType.INFORMATION, "You’re all caught up.").showAndWait();
    }

    public void setAuthService(AuthService authService) {
        this.authService = Objects.requireNonNull(
                authService,
                "authService"
        );
        String username = authService.getUsername();
        if (username == null || username.isBlank()) username = "User";
        String[] parts = username.trim().split("[\\s._-]+");
        String initials = parts.length > 1
                ? parts[0].substring(0, 1) + parts[parts.length - 1].substring(0, 1)
                : username.substring(0, Math.min(2, username.length()));
        initials = initials.toUpperCase(java.util.Locale.ROOT);
        userInitials.setText(initials);
        accountInitials.setText(initials);
        accountName.setText(username);
        userMenu.setAccessibleText("Open account menu for " + username);
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
    private void onTotpEnroll(ActionEvent event) {
        if (authService == null || !authService.isAuthenticated()) return;
        TotpDeviceTestWindow.showEnrollment(((Node) event.getSource()).getScene().getWindow(),
                authService, () -> onLogout(event));
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

            Stage mainStage = (Stage) userMenu.getScene().getWindow();

            // Close authenticated secondary windows, such as the CSE page.
            for (Window window : Window.getWindows().toArray(Window[]::new)) {
                if (window != mainStage) {
                    window.hide();
                }
            }

            kakha.kudava.fdclient.WindowFrame.setContent(mainStage, loginRoot);
            mainStage.setTitle("FD Client - Login");
            mainStage.setWidth(480);
            mainStage.setHeight(640);
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
