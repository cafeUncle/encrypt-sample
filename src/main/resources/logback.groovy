import ch.qos.logback.classic.encoder.PatternLayoutEncoder
import java.nio.charset.Charset
import static ch.qos.logback.classic.Level.INFO

def LOG_HOME = "./logs"

appender("STDOUT", ConsoleAppender) {
    encoder(PatternLayoutEncoder) {
        pattern = "%d{HH:mm:ss.SSS} [%thread] %-5level %logger{50} - %msg%n"
        charset = Charset.forName("utf8")
    }
}


root(INFO, ["STDOUT"])