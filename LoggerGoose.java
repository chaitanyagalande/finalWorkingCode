import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class LoggerGoose {
    private static final String LOG_FILE = "GooseLogs.txt";

    public static void log(String message) {
        try (FileWriter writer = new FileWriter(LOG_FILE, true)) {
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
            writer.write("[" + timestamp + "] " + message + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}