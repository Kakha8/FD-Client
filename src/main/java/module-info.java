module kakha.kudava.fdclient {
    requires javafx.controls;
    requires javafx.fxml;
    requires com.fasterxml.jackson.databind;
    requires java.net.http;
    requires com.sun.jna.platform;


    opens kakha.kudava.fdclient to javafx.fxml;
    exports kakha.kudava.fdclient;
    exports kakha.kudava.fdclient.controller;
    opens kakha.kudava.fdclient.controller to javafx.fxml;
}