package kakha.kudava.fdclient.controller;

import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import javafx.stage.Stage;
import kakha.kudava.fdclient.service.AuthService;

import java.io.IOException;
import java.util.Objects;
import java.util.concurrent.CompletionException;

public class LoginPageController {

    @FXML
    private Button loginButton;

    @FXML
    private TextField usernameField;

    @FXML
    private PasswordField passwordField;

    @FXML
    private Label errorLabel;

    private final AuthService authService = new AuthService();

    @FXML
    private void initialize() {
        setLoginControlsDisabled(true);
        errorLabel.setText("Restoring your session...");

        authService.restoreSession()
                .whenComplete((restored, error) ->
                        Platform.runLater(() -> {
                            if (error != null) {
                                setLoginControlsDisabled(false);
                                showError(getErrorMessage(error));
                                return;
                            }

                            if (Boolean.TRUE.equals(restored)) {
                                openMainPage();
                                return;
                            }

                            setLoginControlsDisabled(false);
                            errorLabel.setText("");
                            usernameField.requestFocus();
                        })
                );
    }

    @FXML
    private void onLogin(ActionEvent event) {
        String username = usernameField.getText().trim();
        String password = passwordField.getText();

        if (username.isBlank() || password.isBlank()) {
            showError("Enter your username and password.");
            return;
        }

        loginButton.setDisable(true);
        errorLabel.setText("");

        authService.login(username, password)
                .whenComplete((accessToken, error) ->
                        Platform.runLater(() -> {
                            loginButton.setDisable(false);
                            passwordField.clear();

                            if (error != null) {
                                showError(getErrorMessage(error));
                                return;
                            }

                            System.out.println("Login successful");
                            openMainPage();
                        })
                );
    }

    private String getErrorMessage(Throwable error) {
        Throwable cause = error;

        if (cause instanceof CompletionException
                && cause.getCause() != null) {
            cause = cause.getCause();
        }

        return cause.getMessage() == null
                ? "Login failed."
                : cause.getMessage();
    }

    private void showError(String message) {
        errorLabel.setText(message);
    }

    private void setLoginControlsDisabled(boolean disabled) {
        loginButton.setDisable(disabled);
        usernameField.setDisable(disabled);
        passwordField.setDisable(disabled);
    }

    private void openMainPage() {
        try {
            FXMLLoader loader = new FXMLLoader(
                    Objects.requireNonNull(
                            getClass().getResource(
                                    "/kakha/kudava/fdclient/main-page.fxml"
                            ),
                            "Could not find main-page.fxml"
                    )
            );

            Parent mainPageRoot = loader.load();

            MainPageController mainPageController = loader.getController();

            /*
             * Pass the same AuthService instance that performed login.
             * It contains the access token and in-memory cookie store.
             */
            mainPageController.setAuthService(authService);

            Stage stage = (Stage) loginButton
                    .getScene()
                    .getWindow();

            Scene currentScene = stage.getScene();
            currentScene.setRoot(mainPageRoot);

            stage.setTitle("FD Client");
            // Use an explicit size because the original Scene was created with
            // the smaller login-page dimensions and can otherwise clip this
            // layout on displays using DPI scaling.
            stage.setWidth(850);
            stage.setHeight(600);
            stage.centerOnScreen();

        } catch (IOException exception) {
            showError("Could not open the main page.");
            exception.printStackTrace();
        }
    }

}
