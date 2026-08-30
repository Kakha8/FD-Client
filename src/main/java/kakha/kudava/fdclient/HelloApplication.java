package kakha.kudava.fdclient;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;
import kakha.kudava.fdclient.service.VirtualDriveService;

import java.io.IOException;

public class HelloApplication extends Application {
    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(HelloApplication.class.getResource("login-page.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 320, 240);
        stage.setTitle("Hello!");
        stage.setScene(scene);
        stage.show();
        // Mount asynchronously as soon as the application opens, even while
        // the login screen is displayed. The main page reuses this mount.
        VirtualDriveService.getInstance().mount().exceptionally(error -> {
            System.err.println("Automatic SSE drive mount failed: " + error.getMessage());
            return null;
        });
    }

    public static void main(String[] args) {
        launch();
    }

    @Override
    public void stop() {
        VirtualDriveService.getInstance().unmount();
    }
}
