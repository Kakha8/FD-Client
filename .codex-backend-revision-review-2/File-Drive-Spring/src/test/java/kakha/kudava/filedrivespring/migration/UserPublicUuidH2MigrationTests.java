package kakha.kudava.filedrivespring.migration;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.sql.*;

import static org.junit.jupiter.api.Assertions.*;

class UserPublicUuidH2MigrationTests {
    @Test
    void migrationBackfillsDistinctUuidsAndIsIdempotent() throws Exception {
        try(Connection connection=DriverManager.getConnection("jdbc:h2:mem:uuid-migration;DB_CLOSE_DELAY=-1","sa","")){
            execute(connection,"CREATE TABLE users (id BIGINT PRIMARY KEY, username VARCHAR(255) NOT NULL)");
            execute(connection,"INSERT INTO users (id,username) VALUES (1,'legacy-a'),(2,'legacy-b')");
            String script=new String(getClass().getResourceAsStream("/db/manual-migrations/V20260820__backfill_user_public_uuid_h2.sql").readAllBytes(),StandardCharsets.UTF_8);
            runScript(connection,script);runScript(connection,script);
            try(Statement statement=connection.createStatement();ResultSet result=statement.executeQuery("SELECT COUNT(*), COUNT(public_uuid), COUNT(DISTINCT public_uuid) FROM users")){
                assertTrue(result.next());assertEquals(2,result.getLong(1));assertEquals(2,result.getLong(2));assertEquals(2,result.getLong(3));
            }
            assertThrows(SQLException.class,()->execute(connection,"INSERT INTO users (id,username,public_uuid) VALUES (3,'duplicate',(SELECT public_uuid FROM users WHERE id=1))"));
            assertThrows(SQLException.class,()->execute(connection,"INSERT INTO users (id,username,public_uuid) VALUES (4,'null-user',NULL)"));
        }
    }
    private static void runScript(Connection connection,String script)throws SQLException{
        String withoutComments=script.replaceAll("(?m)^\\s*--.*$","");
        for(String statement:withoutComments.split(";")){if(!statement.isBlank())execute(connection,statement);}
    }
    private static void execute(Connection connection,String sql)throws SQLException{try(Statement statement=connection.createStatement()){statement.execute(sql);}}
}
