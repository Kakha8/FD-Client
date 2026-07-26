package kakha.kudava.fdclient.controller;

import javafx.application.Platform;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.PasswordField;
import javafx.scene.control.TextField;
import kakha.kudava.fdclient.service.AuthService;

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
                            System.out.println(
                                    "Token received: "
                                            + !accessToken.isBlank()
                            );

                            // Next step:
                            // openMainPage();
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

}
