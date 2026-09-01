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
import javafx.scene.control.TextFormatter;
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
    @FXML private Label eyebrowLabel;
    @FXML private Label headingLabel;
    @FXML private Label descriptionLabel;
    @FXML private Label accountLabel;
    @FXML private VBox credentialsPane;
    @FXML private VBox mfaPane;
    @FXML private TextField codeField;
    @FXML private Button startAgainButton;
    private boolean mfaMode;

    private final AuthService authService = new AuthService();

    @FXML
    private void initialize() {
        errorLabel.visibleProperty().bind(errorLabel.textProperty().isNotEmpty());
        errorLabel.managedProperty().bind(errorLabel.visibleProperty());
        codeField.setTextFormatter(new TextFormatter<String>(change ->
                change.getControlNewText().matches("[0-9]{0,6}") ? change : null));
        setLoginControlsDisabled(true);
        errorLabel.getStyleClass().add("progress");
        errorLabel.setText("Restoring your session...");

        authService.restoreSession()
                .whenComplete((restored, error) ->
                        Platform.runLater(() -> {
                            errorLabel.getStyleClass().remove("progress");
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
        if (mfaMode) { verifyMfa(); return; }
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
                                showMfaPane();
                                return;
                            }
                            openMainPage();
                        })
                );
    }

    private void showMfaPane() {
        mfaMode = true;
        credentialsPane.setVisible(false);
        credentialsPane.setManaged(false);
        mfaPane.setVisible(true);
        mfaPane.setManaged(true);
        startAgainButton.setVisible(true);
        startAgainButton.setManaged(true);
        eyebrowLabel.setText("TWO-STEP SIGN IN");
        headingLabel.setText("Verify your identity");
        descriptionLabel.setText("Enter the six-digit code shown on your authenticator device.");
        accountLabel.setText("Signing in as " + usernameField.getText().trim());
        errorLabel.setText("");
        setLoginControlsDisabled(false);
        codeField.requestFocus();
    }

    @FXML
    private void onStartAgain() {
        authService.cancelMfa();
        mfaMode = false;
        passwordField.clear();
        codeField.clear();
        credentialsPane.setVisible(true);
        credentialsPane.setManaged(true);
        mfaPane.setVisible(false);
        mfaPane.setManaged(false);
        startAgainButton.setVisible(false);
        startAgainButton.setManaged(false);
        eyebrowLabel.setText("WELCOME BACK");
        headingLabel.setText("Sign in to File Drive");
        descriptionLabel.setText("Enter your account details to continue.");
        errorLabel.setText("");
        setLoginControlsDisabled(false);
        passwordField.requestFocus();
    }

    private void verifyMfa() {
        String entered = codeField.getText();
        if (!entered.matches("[0-9]{6}")) {
            showError("Enter exactly six digits.");
            return;
        }
        setLoginControlsDisabled(true);
        errorLabel.setText("");
        authService.completeMfa(entered).whenComplete((token, error) -> Platform.runLater(() -> {
            codeField.clear();
            setLoginControlsDisabled(false);
            if (error != null) {
                showError(getErrorMessage(error));
                codeField.requestFocus();
                return;
            }
            openMainPage();
        }));
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
        codeField.setDisable(disabled);
        startAgainButton.setDisable(disabled);
        loginButton.setText(disabled ? (mfaMode ? "Verifying..." : "Signing in...")
                : (mfaMode ? "Verify and sign in" : "Sign in"));
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
            kakha.kudava.fdclient.WindowFrame.setContent(stage, mainPageRoot);

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
