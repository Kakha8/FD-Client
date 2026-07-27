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

        Stage stage = new Stage();

        FXMLLoader fxmlLoader = new FXMLLoader(HelloApplication.class.getResource("cse-page.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 320, 240);
        stage.setTitle("Hello!");
        stage.setScene(scene);
        stage.show();
    }
}
