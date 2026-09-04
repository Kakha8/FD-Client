package kakha.kudava.fdclient;

import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.beans.binding.Bindings;
import javafx.css.PseudoClass;
import javafx.scene.Cursor;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.MouseButton;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.StackPane;
import javafx.scene.shape.SVGPath;
import javafx.scene.shape.Rectangle;
import javafx.scene.paint.Color;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.stage.WindowEvent;

import java.util.Objects;

/** Main-window chrome, retained when switching between login and account views. */
public final class WindowFrame extends BorderPane {
    private static final double EDGE = 6;
    private final Stage stage;
    private boolean resizing;
    private boolean moving;
    private int resizeEdges;
    private double pressX, pressY, startX, startY, startWidth, startHeight;
    private double dragX, dragY;

    private WindowFrame(Stage stage, Parent content) {
        this.stage = stage;
        getStyleClass().add("window-frame");
        getStylesheets().add(Objects.requireNonNull(getClass().getResource("window-frame.css")).toExternalForm());
        setPadding(new Insets(1));
        setCenter(content);
        // Clip children too, so the title bar and page cannot paint square corners.
        Rectangle outline = new Rectangle();
        outline.widthProperty().bind(widthProperty());
        outline.heightProperty().bind(heightProperty());
        outline.arcWidthProperty().bind(Bindings.when(stage.maximizedProperty()).then(0).otherwise(28));
        outline.arcHeightProperty().bind(outline.arcWidthProperty());
        setClip(outline);
        stage.maximizedProperty().addListener((o, before, maximized) ->
                pseudoClassStateChanged(PseudoClass.getPseudoClass("maximized"), maximized));

        Image windowIcon = new Image(Objects.requireNonNull(getClass().getResource("icon.png")).toExternalForm());
        stage.getIcons().add(windowIcon);
        ImageView icon = new ImageView(windowIcon);
        icon.setFitWidth(19);
        icon.setFitHeight(23);
        icon.setPreserveRatio(true);
        Label title = new Label();
        title.textProperty().bind(stage.titleProperty());
        title.getStyleClass().add("window-title");
        HBox dragArea = new HBox(9, icon, title);
        dragArea.setAlignment(Pos.CENTER_LEFT);
        dragArea.setPadding(new Insets(0, 12, 0, 12));
        dragArea.setMinWidth(0);
        HBox.setHgrow(dragArea, Priority.ALWAYS);

        Button minimize = control("Minimize", "M 1 7 L 11 7");
        minimize.setOnAction(e -> stage.setIconified(true));
        Button maximize = control("Maximize", "M 1 1 L 11 1 L 11 11 L 1 11 Z");
        maximize.disableProperty().bind(stage.resizableProperty().not());
        maximize.setOnAction(e -> toggleMaximized());
        stage.maximizedProperty().addListener((o, old, maximized) -> {
            maximize.setAccessibleText(maximized ? "Restore window" : "Maximize");
            maximize.setGraphic(glyph(maximized
                    ? "M 3 1 L 11 1 L 11 9 M 1 3 L 9 3 L 9 11 L 1 11 Z"
                    : "M 1 1 L 11 1 L 11 11 L 1 11 Z"));
        });
        Button close = control("Close window", "M 1 1 L 11 11 M 11 1 L 1 11");
        close.getStyleClass().add("window-close");
        close.setOnAction(e -> {
            WindowEvent request = new WindowEvent(stage, WindowEvent.WINDOW_CLOSE_REQUEST);
            stage.fireEvent(request);
            if (!request.isConsumed()) stage.hide();
        });
        HBox bar = new HBox(dragArea, minimize, maximize, close);
        bar.setAlignment(Pos.CENTER_LEFT);
        bar.getStyleClass().add("window-titlebar");
        setTop(bar);

        dragArea.setOnMousePressed(e -> {
            if (e.getButton() != MouseButton.PRIMARY || resizing) return;
            moving = true;
            dragX = e.getScreenX() - stage.getX();
            dragY = e.getScreenY() - stage.getY();
        });
        dragArea.setOnMouseDragged(e -> {
            if (!moving || resizing) return;
            if (stage.isMaximized()) {
                double fraction = dragX / stage.getWidth();
                stage.setMaximized(false);
                dragX = stage.getWidth() * fraction;
            }
            stage.setX(e.getScreenX() - dragX);
            stage.setY(e.getScreenY() - dragY);
        });
        dragArea.setOnMouseReleased(e -> moving = false);
        dragArea.setOnMouseClicked(e -> {
            if (e.getButton() == MouseButton.PRIMARY && e.getClickCount() == 2) toggleMaximized();
        });
        installResize();
    }

    public static Scene createScene(Stage stage, Parent content, double width, double height) {
        stage.initStyle(StageStyle.TRANSPARENT);
        Scene scene = new Scene(new WindowFrame(stage, content), width, height + 36);
        scene.setFill(Color.TRANSPARENT);
        return scene;
    }

    public static void setContent(Stage stage, Parent content) {
        if (stage.getScene().getRoot() instanceof WindowFrame frame) frame.setCenter(content);
        else stage.getScene().setRoot(content);
    }

    private void toggleMaximized() {
        if (stage.isResizable()) stage.setMaximized(!stage.isMaximized());
    }

    private Button control(String name, String path) {
        Button button = new Button();
        button.setAccessibleText(name);
        button.setGraphic(glyph(path));
        button.getStyleClass().add("window-control");
        button.setFocusTraversable(false);
        return button;
    }

    private StackPane glyph(String path) {
        SVGPath shape = new SVGPath();
        shape.setContent(path);
        shape.getStyleClass().add("window-glyph");
        StackPane box = new StackPane(shape);
        box.setMinSize(14, 14);
        box.setPrefSize(14, 14);
        box.setMaxSize(14, 14);
        box.setMouseTransparent(true);
        return box;
    }

    private int edges(MouseEvent event) {
        if (stage.isMaximized() || !stage.isResizable()) return 0;
        double x = event.getSceneX(), y = event.getSceneY();
        return (x < EDGE ? 1 : x > getWidth() - EDGE ? 2 : 0)
                | (y < EDGE ? 4 : y > getHeight() - EDGE ? 8 : 0);
    }

    private Cursor cursor(int edges) {
        return switch (edges) {
            case 1, 2 -> Cursor.H_RESIZE;
            case 4, 8 -> Cursor.V_RESIZE;
            case 5, 10 -> Cursor.NW_RESIZE;
            case 6, 9 -> Cursor.NE_RESIZE;
            default -> Cursor.DEFAULT;
        };
    }

    private void installResize() {
        addEventFilter(MouseEvent.MOUSE_MOVED, e -> setCursor(cursor(edges(e))));
        addEventFilter(MouseEvent.MOUSE_PRESSED, e -> {
            if (e.getButton() != MouseButton.PRIMARY) return;
            resizeEdges = edges(e);
            resizing = resizeEdges != 0;
            if (!resizing) return;
            pressX = e.getScreenX(); pressY = e.getScreenY();
            startX = stage.getX(); startY = stage.getY();
            startWidth = stage.getWidth(); startHeight = stage.getHeight();
            e.consume();
        });
        addEventFilter(MouseEvent.MOUSE_DRAGGED, e -> {
            if (!resizing) return;
            double dx = e.getScreenX() - pressX, dy = e.getScreenY() - pressY;
            if ((resizeEdges & 3) != 0) {
                double width = Math.max(stage.getMinWidth(), startWidth + ((resizeEdges & 1) != 0 ? -dx : dx));
                stage.setWidth(width);
                if ((resizeEdges & 1) != 0) stage.setX(startX + startWidth - width);
            }
            if ((resizeEdges & 12) != 0) {
                double height = Math.max(stage.getMinHeight(), startHeight + ((resizeEdges & 4) != 0 ? -dy : dy));
                stage.setHeight(height);
                if ((resizeEdges & 4) != 0) stage.setY(startY + startHeight - height);
            }
            e.consume();
        });
        addEventFilter(MouseEvent.MOUSE_RELEASED, e -> {
            if (resizing) { resizing = false; setCursor(Cursor.DEFAULT); e.consume(); }
        });
    }
}
