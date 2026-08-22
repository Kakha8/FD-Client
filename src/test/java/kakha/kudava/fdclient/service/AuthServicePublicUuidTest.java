package kakha.kudava.fdclient.service;

import org.junit.jupiter.api.Test;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AuthServicePublicUuidTest {

    @Test
    void parsesCanonicalPublicUuid() {
        UUID expected = UUID.fromString(
                "8c98baef-9c78-45d3-8797-b27e9786fa26"
        );

        assertEquals(
                expected,
                AuthService.parsePublicUuid(expected.toString())
        );
    }

    @Test
    void rejectsMissingPublicUuid() {
        assertThrows(
                AuthService.AuthException.class,
                () -> AuthService.parsePublicUuid(null)
        );

        assertThrows(
                AuthService.AuthException.class,
                () -> AuthService.parsePublicUuid("   ")
        );
    }

    @Test
    void rejectsMalformedPublicUuid() {
        assertThrows(
                AuthService.AuthException.class,
                () -> AuthService.parsePublicUuid("not-a-uuid")
        );
    }

    @Test
    void newServiceIsNotAuthenticated() {
        assertFalse(new AuthService().isAuthenticated());
    }
}
