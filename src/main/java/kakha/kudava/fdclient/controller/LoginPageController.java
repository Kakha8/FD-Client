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
import javafx.scene.control.Dialog;
import javafx.scene.control.ButtonType;
import javafx.scene.control.ButtonBar;
import javafx.scene.layout.VBox;
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

        setLoginControlsDisabled(true);
        errorLabel.setText("");

        authService.login(username, password)
                .whenComplete((result, error) ->
                        Platform.runLater(() -> {
                            setLoginControlsDisabled(false);
                            passwordField.clear();

                            if (error != null) {
                                showError(getErrorMessage(error));
                                return;
                            }

                            if (result.mfaRequired()) {
                                showMfaDialog();
                                return;
                            }
                            openMainPage();
                        })
                );
    }

    private void showMfaDialog() {
        setLoginControlsDisabled(true);
        Dialog<Void> dialog = new Dialog<>();
        dialog.initOwner(loginButton.getScene().getWindow());
        dialog.setTitle("Authenticator code");
        TextField code = new TextField();
        code.setPromptText("Six-digit code on your ESP32");
        Label message = new Label("Enter the current code. After enrollment, wait for the next code.");
        message.setWrapText(true);
        dialog.getDialogPane().setContent(new VBox(10, message, code));
        dialog.getDialogPane().setPrefWidth(430);
        ButtonType verifyType = new ButtonType("Verify", ButtonBar.ButtonData.OK_DONE);
        ButtonType restartType = new ButtonType("Start again", ButtonBar.ButtonData.CANCEL_CLOSE);
        dialog.getDialogPane().getButtonTypes().addAll(verifyType, restartType);
        Button verify = (Button) dialog.getDialogPane().lookupButton(verifyType);
        Button restart = (Button) dialog.getDialogPane().lookupButton(restartType);
        boolean[] sending = {false};
        boolean[] succeeded = {false};
        dialog.setOnCloseRequest(e -> { if (sending[0]) e.consume(); });
        verify.addEventFilter(ActionEvent.ACTION, e -> {
            e.consume();
            String entered = code.getText().trim();
            if (!entered.matches("[0-9]{6}")) { message.setText("Enter exactly six digits."); return; }
            sending[0] = true;
            verify.setDisable(true);
            restart.setDisable(true);
            code.clear();
            message.setText("Verifying...");
            authService.completeMfa(entered).whenComplete((token, error) -> Platform.runLater(() -> {
                sending[0] = false;
                verify.setDisable(false);
                restart.setDisable(false);
                if (error != null) { message.setText(getErrorMessage(error)); return; }
                succeeded[0] = true;
                dialog.close();
                openMainPage();
            }));
        });
        dialog.setOnHidden(e -> {
            code.clear();
            if (!succeeded[0]) authService.cancelMfa();
            setLoginControlsDisabled(false);
        });
        dialog.show();
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
