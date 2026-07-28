package kakha.kudava.fdclient.controller;

import javafx.event.ActionEvent;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import kakha.kudava.fdclient.HelloApplication;
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
