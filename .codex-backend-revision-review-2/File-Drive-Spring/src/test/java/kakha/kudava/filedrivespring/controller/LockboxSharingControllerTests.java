package kakha.kudava.filedrivespring.controller;

import kakha.kudava.filedrivespring.dto.lockbox.LockboxCreateShareRequest;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxRecipientKeysResponse;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxReceivedShareResponse;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxReceivedSharesResponse;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxShareResponse;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxOwnDeviceKeyResponse;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxOwnDeviceResponse;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxOwnDevicesResponse;
import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import kakha.kudava.filedrivespring.services.lockbox.LockboxSharingService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.time.Instant;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:h2:mem:sharing-controller-test;DB_CLOSE_DELAY=-1",
        "spring.datasource.username=sa", "spring.datasource.password=",
        "s3.endpoint=http://localhost:9000", "s3.access-key=test", "s3.secret-key=test",
        "s3.lockbox-bucket=test", "s3.bucket=test",
        "app.jwt.secret=0123456789012345678901234567890123456789012345678901234567890123",
        "ADMIN_PASSWORD=test-password", "JWT_REFRESH_DAYS=7", "quarantine.retention-days=30",
        "server.ssl.enabled=false"
})
@AutoConfigureMockMvc
class LockboxSharingControllerTests {
    @Autowired MockMvc mvc;
    @MockitoBean LockboxSharingService sharingService;

    @Test
    void unauthenticatedSharingRoutesAreRejected() throws Exception {
        mvc.perform(get("/api/lockbox/share-recipients/alice/keys"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/lockbox/devices"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/lockbox/shares/received"))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/lockbox/shares/received/11223344-5566-4788-99aa-bbccddeeff00"))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/lockbox/shares")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(roles = "USER")
    void ownDevicesReturnsEncryptionKeysAndHonorsExclusion() throws Exception {
        UUID excluded = UUID.randomUUID();
        UUID target = UUID.randomUUID();
        when(sharingService.ownDevices(excluded)).thenReturn(new LockboxOwnDevicesResponse(List.of(
                new LockboxOwnDeviceResponse(target, "Laptop", "ACTIVE", List.of(
                        new LockboxOwnDeviceKeyResponse("key-id", "ML_KEM_1024", "public-key")))
        )));

        mvc.perform(get("/api/lockbox/devices").param("excludeDeviceId", excluded.toString()))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.devices[0].deviceId").value(target.toString()))
                .andExpect(jsonPath("$.devices[0].encryptionKeys[0].algorithm").value("ML_KEM_1024"));
        verify(sharingService).ownDevices(excluded);
    }

    @Test
    @WithMockUser(roles = "USER")
    void receivedListAndIndividualReturnNoStoreContracts() throws Exception {
        UUID shareId = UUID.fromString("11223344-5566-4788-99aa-bbccddeeff00");
        UUID deviceId = UUID.randomUUID();
        LockboxReceivedShareResponse share = received(shareId);
        when(sharingService.receivedShares(deviceId))
                .thenReturn(new LockboxReceivedSharesResponse(List.of(share)));
        when(sharingService.receivedShare(shareId, deviceId)).thenReturn(share);

        mvc.perform(get("/api/lockbox/shares/received").param("deviceId", deviceId.toString()))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.shares").isArray())
                .andExpect(jsonPath("$.shares[0].shareId").value(shareId.toString()));
        mvc.perform(get("/api/lockbox/shares/received/{shareUuid}", shareId)
                        .param("deviceId", deviceId.toString()))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.shareId").value(shareId.toString()));
    }

    @Test
    @WithMockUser(roles = "USER")
    void unavailableAndMalformedReceivedShareIdsAreStableClientErrors() throws Exception {
        UUID shareId = UUID.randomUUID();
        UUID deviceId = UUID.randomUUID();
        when(sharingService.receivedShare(shareId, deviceId)).thenThrow(new LockboxApiException(
                "LOCKBOX_SHARE_UNAVAILABLE", HttpStatus.NOT_FOUND,
                "The shared Lockbox file is unavailable."));

        mvc.perform(get("/api/lockbox/shares/received/{shareUuid}", shareId)
                        .param("deviceId", deviceId.toString()))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.error").value("LOCKBOX_SHARE_UNAVAILABLE"));
        mvc.perform(get("/api/lockbox/shares/received/not-a-uuid")
                        .param("deviceId", deviceId.toString()))
                .andExpect(status().is4xxClientError());
    }

    private static LockboxReceivedShareResponse received(UUID shareId) {
        return new LockboxReceivedShareResponse(
                shareId.toString(), 10L, UUID.randomUUID().toString(), 1L,
                "owner", "READ", Instant.now(), null,
                "envelope", "key-id", "public-key", "share-signature",
                "manifest", "file-signature", "header"
        );
    }

    @Test
    @WithMockUser(roles = "USER")
    void createReturns201NoStoreAndPassesDtoUnchanged() throws Exception {
        LockboxShareResponse response = new LockboxShareResponse(
                UUID.randomUUID().toString(), 10L, "owner", "recipient", "key", "ACTIVE"
        );
        when(sharingService.createShare(any())).thenReturn(response);

        mvc.perform(post("/api/lockbox/shares")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"fileId":10,"envelope":"env","ownerSigningKeyId":"key","ownerSignature":"sig"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.status").value("ACTIVE"));

        verify(sharingService).createShare(new LockboxCreateShareRequest(10L, "env", "key", "sig"));
    }

    @Test
    @WithMockUser(roles = "USER")
    void recipientKeysReturnsNoStore() throws Exception {
        when(sharingService.recipientEncryptionKeys("alice")).thenReturn(
                new LockboxRecipientKeysResponse(2L, UUID.randomUUID(), "alice", List.of())
        );
        mvc.perform(get("/api/lockbox/share-recipients/alice/keys"))
                .andExpect(status().isOk())
                .andExpect(header().string("Cache-Control", "no-store"));
    }

    @Test
    @WithMockUser(roles = "USER")
    void malformedJsonAndBase64AreClientErrorsNotServerErrors() throws Exception {
        mvc.perform(post("/api/lockbox/shares")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{"))
                .andExpect(status().isBadRequest());

        when(sharingService.createShare(any())).thenThrow(LockboxApiException.bad(
                "INVALID_LOCKBOX_SHARE", "envelope is not valid Base64."
        ));
        mvc.perform(post("/api/lockbox/shares")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"fileId":10,"envelope":"!","ownerSigningKeyId":"!","ownerSignature":"!"}
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("INVALID_LOCKBOX_SHARE"));
    }
}
