package kakha.kudava.filedrivespring.model;

import jakarta.persistence.EntityManager;
import kakha.kudava.filedrivespring.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest(properties="spring.jpa.hibernate.ddl-auto=create-drop")
class UserPublicUuidPersistenceTests {
    @Autowired UserRepository users;
    @Autowired EntityManager entityManager;

    @Test
    void newUsersReceiveDistinctStablePublicUuids() {
        User first=save("uuid-first"),second=save("uuid-second");
        assertNotNull(first.getPublicUuid());assertNotNull(second.getPublicUuid());assertNotEquals(first.getPublicUuid(),second.getPublicUuid());
        UUID original=first.getPublicUuid();first.setUsername("uuid-first-renamed");users.saveAndFlush(first);entityManager.clear();
        assertEquals(original,users.findById(first.getId()).orElseThrow().getPublicUuid());
    }

    private User save(String name){User u=new User();u.setUsername(name);u.setPassword("x");u.setRole(User.Role.USER);return users.saveAndFlush(u);}
}
