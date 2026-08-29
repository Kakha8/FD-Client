package kakha.kudava.fdclient.controller;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.stage.Stage;
import javafx.stage.Window;
import kakha.kudava.fdclient.service.AuthService;

import java.io.IOException;
import java.util.Objects;

public class MainPageController {
    private AuthService authService;

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
    private void onLogout(ActionEvent event) {
        if (authService == null) {
            throw new IllegalStateException(
                    "No authentication session is available."
            );
        }

        try {
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
