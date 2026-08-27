package kakha.kudava.filedrivespring.migration;

import org.h2.tools.RunScript;
import org.junit.jupiter.api.Test;

import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LockboxShareEnvelopeV1H2MigrationTests {
    @Test
    void migratesLegacySharingSchemaWithoutLosingHistoryOrConstraints() throws Exception {
        try (Connection connection = DriverManager.getConnection(
                "jdbc:h2:mem:share-envelope-migration;DB_CLOSE_DELAY=-1", "sa", ""
        )) {
            RunScript.execute(connection, new StringReader(legacySchema()));
            String migration = Files.readString(Path.of(
                    "src/main/resources/db/manual-migrations/V20260822__lockbox_share_envelope_v1_h2.sql"
            ));
            RunScript.execute(connection, new StringReader(migration));
            RunScript.execute(connection, new StringReader(migration));

            assertTrue(columnExists(connection, "LOCKBOX_SHARES", "EXPIRES_AT"));
            assertTrue(columnExists(connection, "LOCKBOX_SHARE_ENVELOPES", "ENVELOPE"));
            assertEquals("YES", nullable(connection, "LOCKBOX_SHARE_ENVELOPES", "KEM_CIPHERTEXT"));
            assertEquals("YES", nullable(connection, "LOCKBOX_SHARE_ENVELOPES", "WRAP_NONCE"));
            assertEquals("YES", nullable(connection, "LOCKBOX_SHARE_ENVELOPES", "WRAPPED_DEK"));
            assertEquals("YES", nullable(connection, "LOCKBOX_SHARE_ENVELOPES", "ENVELOPE"));
            assertEquals(1, scalar(connection, "SELECT COUNT(*) FROM lockbox_shares WHERE id=1"));
            assertEquals(1, scalar(connection, "SELECT COUNT(*) FROM lockbox_share_envelopes WHERE id=1"));

            try (Statement statement = connection.createStatement()) {
                statement.executeUpdate("""
                        INSERT INTO lockbox_shares
                        (id,share_uuid,lockbox_file_id,owner_user_id,recipient_user_id,status,permission,created_at,expires_at)
                        VALUES (2,'22222222-2222-4222-8222-222222222222',10,1,2,'ACTIVE','READ',CURRENT_TIMESTAMP,NULL)
                        """);
                statement.executeUpdate("""
                        INSERT INTO lockbox_share_envelopes
                        (id,share_id,recipient_key_id,owner_signing_key_id,envelope,owner_signature,created_at)
                        VALUES (2,2,20,21,SPACE(1858),SPACE(4627),CURRENT_TIMESTAMP)
                        """);
            }
            assertEquals(1, scalar(connection,
                    "SELECT COUNT(*) FROM lockbox_share_envelopes WHERE id=2 AND OCTET_LENGTH(envelope)=1858 AND OCTET_LENGTH(owner_signature)=4627"));

            assertThrows(SQLException.class, () -> execute(connection, """
                    INSERT INTO lockbox_shares
                    (id,share_uuid,lockbox_file_id,owner_user_id,recipient_user_id,status,permission,created_at)
                    VALUES (3,'22222222-2222-4222-8222-222222222222',10,1,2,'ACTIVE','READ',CURRENT_TIMESTAMP)
                    """));
            assertThrows(SQLException.class, () -> execute(connection, """
                    INSERT INTO lockbox_shares
                    (id,share_uuid,lockbox_file_id,owner_user_id,recipient_user_id,status,permission,created_at)
                    VALUES (4,'44444444-4444-4444-8444-444444444444',999,1,2,'ACTIVE','READ',CURRENT_TIMESTAMP)
                    """));
        }
    }

    private static String legacySchema() {
        return """
                CREATE TABLE users(id BIGINT PRIMARY KEY);
                CREATE TABLE lockbox_files(id BIGINT PRIMARY KEY);
                CREATE TABLE lockbox_keys(id BIGINT PRIMARY KEY);
                INSERT INTO users VALUES(1),(2);
                INSERT INTO lockbox_files VALUES(10);
                INSERT INTO lockbox_keys VALUES(20),(21);
                CREATE TABLE lockbox_shares(
                    id BIGINT PRIMARY KEY,
                    share_uuid UUID NOT NULL,
                    lockbox_file_id BIGINT NOT NULL,
                    owner_user_id BIGINT NOT NULL,
                    recipient_user_id BIGINT NOT NULL,
                    status VARCHAR(20) NOT NULL,
                    permission VARCHAR(20) NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    CONSTRAINT uk_lockbox_share_uuid UNIQUE(share_uuid),
                    CONSTRAINT uk_lockbox_share_file_recipient UNIQUE(lockbox_file_id,recipient_user_id),
                    CONSTRAINT fk_share_file FOREIGN KEY(lockbox_file_id) REFERENCES lockbox_files(id),
                    CONSTRAINT fk_share_owner FOREIGN KEY(owner_user_id) REFERENCES users(id),
                    CONSTRAINT fk_share_recipient FOREIGN KEY(recipient_user_id) REFERENCES users(id)
                );
                CREATE TABLE lockbox_share_envelopes(
                    id BIGINT PRIMARY KEY,
                    share_id BIGINT NOT NULL,
                    recipient_key_id BIGINT NOT NULL,
                    owner_signing_key_id BIGINT NOT NULL,
                    kem_ciphertext BLOB NOT NULL,
                    wrap_nonce BLOB NOT NULL,
                    wrapped_dek BLOB NOT NULL,
                    owner_signature BLOB NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    CONSTRAINT fk_envelope_share FOREIGN KEY(share_id) REFERENCES lockbox_shares(id),
                    CONSTRAINT fk_envelope_recipient_key FOREIGN KEY(recipient_key_id) REFERENCES lockbox_keys(id),
                    CONSTRAINT fk_envelope_owner_key FOREIGN KEY(owner_signing_key_id) REFERENCES lockbox_keys(id)
                );
                INSERT INTO lockbox_shares VALUES
                    (1,'11111111-1111-4111-8111-111111111111',10,1,2,'REVOKED','READ',CURRENT_TIMESTAMP);
                INSERT INTO lockbox_share_envelopes VALUES
                    (1,1,20,21,X'01',X'02',X'03',X'04',CURRENT_TIMESTAMP);
                """;
    }

    private static boolean columnExists(Connection connection, String table, String column) throws SQLException {
        try (ResultSet result = connection.getMetaData().getColumns(null, null, table, column)) {
            return result.next();
        }
    }
    private static String nullable(Connection connection, String table, String column) throws SQLException {
        try (var statement = connection.prepareStatement("""
                SELECT IS_NULLABLE FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_NAME=? AND COLUMN_NAME=?
                """)) {
            statement.setString(1, table); statement.setString(2, column);
            try (ResultSet result = statement.executeQuery()) { result.next(); return result.getString(1); }
        }
    }
    private static int scalar(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement(); ResultSet result = statement.executeQuery(sql)) {
            result.next(); return result.getInt(1);
        }
    }
    private static void execute(Connection connection, String sql) throws SQLException {
        try (Statement statement = connection.createStatement()) { statement.executeUpdate(sql); }
    }
}
