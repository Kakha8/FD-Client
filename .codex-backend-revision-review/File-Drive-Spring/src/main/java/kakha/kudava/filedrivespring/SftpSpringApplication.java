package kakha.kudava.filedrivespring;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class SftpSpringApplication {

    public static void main(String[] args) {
        SpringApplication.run(SftpSpringApplication.class, args);
    }

}
