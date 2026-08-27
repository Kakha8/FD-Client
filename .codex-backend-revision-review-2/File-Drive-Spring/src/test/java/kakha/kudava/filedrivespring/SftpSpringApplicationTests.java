package kakha.kudava.filedrivespring;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:lockbox-test;DB_CLOSE_DELAY=-1",
        "spring.datasource.username=sa", "spring.datasource.password=",
        "s3.endpoint=http://localhost:9000", "s3.access-key=test", "s3.secret-key=test",
        "s3.lockbox-bucket=test", "s3.bucket=test", "app.jwt.secret=0123456789012345678901234567890123456789012345678901234567890123",
        "ADMIN_PASSWORD=test-password",
        "JWT_REFRESH_DAYS=7",
        "quarantine.retention-days=30",
        "server.ssl.enabled=false"
})
class SftpSpringApplicationTests {

    @Test
    void contextLoads() {
    }

}
