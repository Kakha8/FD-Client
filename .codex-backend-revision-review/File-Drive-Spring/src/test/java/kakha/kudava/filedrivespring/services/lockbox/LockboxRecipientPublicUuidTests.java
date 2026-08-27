package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import kakha.kudava.filedrivespring.model.*;
import kakha.kudava.filedrivespring.repository.*;
import kakha.kudava.filedrivespring.services.ResourceAccessService;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class LockboxRecipientPublicUuidTests {
    @Test
    void lookupReturnsSelectedRecipientsPublicUuid() {
        Fixture fixture = new Fixture();
        UUID requesterUuid=UUID.randomUUID(), recipientUuid=UUID.randomUUID();
        User requester=user(1L,"owner",requesterUuid); User recipient=user(2L,"gela",recipientUuid);
        when(fixture.access.currentUser()).thenReturn(requester);
        when(fixture.users.findByUsername("gela")).thenReturn(Optional.of(recipient));
        when(fixture.keys.findAllByDeviceProfileUserIdAndDeviceStatusAndRoleAndStatus(
                2L,LockboxDevice.Status.ACTIVE,LockboxKey.Role.ENCRYPTION,LockboxKey.Status.ACTIVE))
                .thenReturn(List.of(encryptionKey(recipient)));

        var response=fixture.service().recipientEncryptionKeys("gela");
        assertEquals(recipientUuid,response.recipientPublicUuid());
        assertNotEquals(requesterUuid,response.recipientPublicUuid());
        assertEquals(2L,response.recipientId());
        assertEquals(1,response.encryptionKeys().size());
    }

    @Test
    void recipientWithoutPersistedUuidIsUnavailable() {
        Fixture fixture=new Fixture(); User requester=user(1L,"owner",UUID.randomUUID());User recipient=user(2L,"legacy",null);
        when(fixture.access.currentUser()).thenReturn(requester);when(fixture.users.findByUsername("legacy")).thenReturn(Optional.of(recipient));
        when(fixture.keys.findAllByDeviceProfileUserIdAndDeviceStatusAndRoleAndStatus(anyLong(),any(),any(),any()))
                .thenReturn(List.of(encryptionKey(recipient)));
        LockboxApiException error=assertThrows(LockboxApiException.class,()->fixture.service().recipientEncryptionKeys("legacy"));
        assertEquals("LOCKBOX_RECIPIENT_UNAVAILABLE",error.getCode());
    }

    private static LockboxKey encryptionKey(User user){
        LockboxProfile profile=new LockboxProfile(user);LockboxDevice device=new LockboxDevice(profile,UUID.randomUUID(),new byte[32],"device");
        return new LockboxKey(device,LockboxKey.Role.ENCRYPTION,LockboxKey.Algorithm.ML_KEM_1024,new byte[32],new byte[]{1});
    }
    private static User user(Long id,String name,UUID uuid){User u=new User();u.setId(id);u.setUsername(name);u.setPublicUuid(uuid);return u;}
    private static final class Fixture {
        final UserRepository users=mock(UserRepository.class);final LockboxKeyRepository keys=mock(LockboxKeyRepository.class);
        final ResourceAccessService access=mock(ResourceAccessService.class);
        LockboxSharingService service(){return new LockboxSharingService(users,keys,access,mock(LockboxFileRepository.class),mock(LockboxFileRevisionRepository.class),mock(LockboxShareRepository.class),mock(LockboxShareEnvelopeRepository.class),new LockboxShareEnvelopeParser(),mock(LockboxSignatureVerifier.class),mock(LockboxObjectStorage.class),mock(LockboxDeviceRepository.class));}
    }
}
