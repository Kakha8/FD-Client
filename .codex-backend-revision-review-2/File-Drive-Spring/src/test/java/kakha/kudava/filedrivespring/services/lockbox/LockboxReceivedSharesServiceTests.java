package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import kakha.kudava.filedrivespring.model.*;
import kakha.kudava.filedrivespring.repository.*;
import kakha.kudava.filedrivespring.services.ResourceAccessService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class LockboxReceivedSharesServiceTests {

    @Test
    void emptyListUsesAuthenticatedRecipientActiveAndDatabaseCap() throws Exception {
        Fixture fixture = new Fixture();
        when(fixture.shares.findReceivedAvailableShares(eq(2L), eq(fixture.deviceUuid), eq(LockboxShare.Status.ACTIVE),
                any(Instant.class), any(Pageable.class))).thenReturn(List.of());

        var response = fixture.service.receivedShares(fixture.deviceUuid);

        assertTrue(response.shares().isEmpty());
        assertThrows(UnsupportedOperationException.class, () -> response.shares().add(null));
        ArgumentCaptor<Pageable> page = ArgumentCaptor.forClass(Pageable.class);
        verify(fixture.shares).findReceivedAvailableShares(eq(2L), eq(fixture.deviceUuid), eq(LockboxShare.Status.ACTIVE),
                any(Instant.class), page.capture());
        assertEquals(100, page.getValue().getPageSize());
    }

    @Test
    void validSingleReturnsExactBase64ArtifactsAndReadsOnlyHeader() throws Exception {
        Fixture fixture = new Fixture();
        fixture.stubValidArtifacts();
        when(fixture.shares.findReceivedAvailableShare(eq(fixture.shareUuid), eq(2L), eq(fixture.deviceUuid),
                eq(LockboxShare.Status.ACTIVE), any(Instant.class))).thenReturn(Optional.of(fixture.share));

        var response = fixture.service.receivedShare(fixture.shareUuid, fixture.deviceUuid);

        assertEquals(fixture.shareUuid.toString(), response.shareId());
        assertEquals(Base64.getEncoder().encodeToString(fixture.envelopeBytes), response.recipientEnvelope());
        assertEquals(Base64.getEncoder().encodeToString(fixture.manifest), response.manifest());
        assertEquals(Base64.getEncoder().encodeToString(fixture.signature), response.fileSignature());
        assertEquals(Base64.getEncoder().encodeToString(fixture.header), response.encryptedHeader());
        verify(fixture.storage).download("container");
    }

    @Test
    void nullUnknownAndMissingEnvelopeUseSameUnavailableResponse() throws Exception {
        Fixture fixture = new Fixture();
        assertUnavailable(assertThrows(LockboxApiException.class,
                () -> fixture.service.receivedShare(null, fixture.deviceUuid)));
        when(fixture.shares.findReceivedAvailableShare(eq(fixture.shareUuid), eq(2L), eq(fixture.deviceUuid), any(), any()))
                .thenReturn(Optional.empty());
        assertUnavailable(assertThrows(LockboxApiException.class,
                () -> fixture.service.receivedShare(fixture.shareUuid, fixture.deviceUuid)));
        when(fixture.shares.findReceivedAvailableShare(eq(fixture.shareUuid), eq(2L), eq(fixture.deviceUuid), any(), any()))
                .thenReturn(Optional.of(fixture.share));
        when(fixture.envelopes.findByShareId(9L)).thenReturn(Optional.empty());
        assertUnavailable(assertThrows(LockboxApiException.class,
                () -> fixture.service.receivedShare(fixture.shareUuid, fixture.deviceUuid)));
    }

    @Test
    void relationalRecipientMismatchIsUnavailableBeforeStorageReads() throws Exception {
        Fixture fixture = new Fixture();
        when(fixture.shares.findReceivedAvailableShare(eq(fixture.shareUuid), eq(2L), eq(fixture.deviceUuid), any(), any()))
                .thenReturn(Optional.of(fixture.share));
        when(fixture.envelopes.findByShareId(9L)).thenReturn(Optional.of(fixture.envelope));
        when(fixture.keyOwner.getId()).thenReturn(3L);

        assertUnavailable(assertThrows(LockboxApiException.class,
                () -> fixture.service.receivedShare(fixture.shareUuid, fixture.deviceUuid)));
        verifyNoInteractions(fixture.storage);
    }

    @Test
    void truncatedOversizedAndTrailingArtifactsAreUnavailable() throws Exception {
        Fixture truncated = new Fixture(); truncated.stubRelation();
        when(truncated.storage.size("manifest")).thenReturn(4L);
        when(truncated.storage.download("manifest")).thenReturn(new ByteArrayInputStream(new byte[3]));
        assertUnavailable(callSingle(truncated));

        Fixture oversized = new Fixture(); oversized.stubRelation();
        when(oversized.storage.size("manifest")).thenReturn(1_025L);
        assertUnavailable(callSingle(oversized));
        verify(oversized.storage, never()).download("manifest");

        Fixture trailing = new Fixture(); trailing.stubRelation();
        when(trailing.storage.size("manifest")).thenReturn(3L);
        when(trailing.storage.download("manifest")).thenReturn(new ByteArrayInputStream(new byte[4]));
        assertUnavailable(callSingle(trailing));
    }

    @Test
    void malformedAndTruncatedHeadersAreUnavailable() throws Exception {
        Fixture malformed = new Fixture(); malformed.stubThroughSignature();
        byte[] bad = new byte[32]; ByteBuffer.wrap(bad, 12, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(31);
        when(malformed.storage.size("container")).thenReturn(32L);
        when(malformed.storage.download("container")).thenReturn(new ByteArrayInputStream(bad));
        assertUnavailable(callSingle(malformed));

        Fixture truncated = new Fixture(); truncated.stubThroughSignature();
        byte[] preamble = new byte[32]; ByteBuffer.wrap(preamble, 12, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(40);
        when(truncated.storage.size("container")).thenReturn(40L);
        when(truncated.storage.download("container")).thenReturn(new ByteArrayInputStream(preamble));
        assertUnavailable(callSingle(truncated));
    }

    private static LockboxApiException callSingle(Fixture fixture) {
        return assertThrows(LockboxApiException.class,
                () -> fixture.service.receivedShare(fixture.shareUuid, fixture.deviceUuid));
    }

    private static void assertUnavailable(LockboxApiException exception) {
        assertEquals("LOCKBOX_SHARE_UNAVAILABLE", exception.getCode());
        assertEquals(HttpStatus.NOT_FOUND, exception.getStatus());
    }

    private static final class Fixture {
        final UserRepository users = mock(UserRepository.class);
        final LockboxKeyRepository keys = mock(LockboxKeyRepository.class);
        final ResourceAccessService access = mock(ResourceAccessService.class);
        final LockboxFileRepository files = mock(LockboxFileRepository.class);
        final LockboxFileRevisionRepository revisions = mock(LockboxFileRevisionRepository.class);
        final LockboxShareRepository shares = mock(LockboxShareRepository.class);
        final LockboxShareEnvelopeRepository envelopes = mock(LockboxShareEnvelopeRepository.class);
        final LockboxObjectStorage storage = mock(LockboxObjectStorage.class);
        final LockboxDeviceRepository devices = mock(LockboxDeviceRepository.class);
        final LockboxShareEnvelopeParser parser = mock(LockboxShareEnvelopeParser.class);
        final LockboxSharingService service = new LockboxSharingService(users, keys, access, files,
                revisions, shares, envelopes, parser, mock(LockboxSignatureVerifier.class), storage, devices);
        final UUID shareUuid = UUID.randomUUID();
        final UUID deviceUuid = UUID.randomUUID();
        final User recipient = mock(User.class), owner = mock(User.class), keyOwner = mock(User.class);
        final LockboxShare share = mock(LockboxShare.class);
        final LockboxFile file = mock(LockboxFile.class);
        final LockboxFileRevision revision = mock(LockboxFileRevision.class);
        final LockboxShareEnvelope envelope = mock(LockboxShareEnvelope.class);
        final LockboxKey recipientKey = mock(LockboxKey.class), signingKey = mock(LockboxKey.class);
        final LockboxDevice device = mock(LockboxDevice.class);
        final LockboxProfile profile = mock(LockboxProfile.class);
        final byte[] envelopeBytes = new byte[]{1, 2}, manifest = new byte[]{3, 4}, signature = new byte[]{5, 6};
        final byte[] header = header(40);

        Fixture() {
            when(access.currentUser()).thenReturn(recipient); when(recipient.getId()).thenReturn(2L);
            when(devices.findOwnedActiveDevice(deviceUuid, 2L, LockboxDevice.Status.ACTIVE)).thenReturn(Optional.of(device));
            when(device.getDeviceUuid()).thenReturn(deviceUuid);
            when(share.getId()).thenReturn(9L); when(share.getShareUuid()).thenReturn(shareUuid);
            when(share.getRecipient()).thenReturn(recipient); when(share.getOwner()).thenReturn(owner);
            when(owner.getUsername()).thenReturn("owner"); when(share.getPermission()).thenReturn(LockboxShare.Permission.READ);
            when(share.getRevision()).thenReturn(revision); when(revision.getLockboxFile()).thenReturn(file); when(file.getId()).thenReturn(10L);
            when(share.getTargetDevice()).thenReturn(device);
            when(file.getClientFileId()).thenReturn(UUID.randomUUID()); when(revision.getRevision()).thenReturn(7L);
            when(revision.getManifestObjectKey()).thenReturn("manifest"); when(revision.getSignatureObjectKey()).thenReturn("signature");
            when(revision.getContainerObjectKey()).thenReturn("container");
            when(envelope.getRecipientKey()).thenReturn(recipientKey); when(recipientKey.getDevice()).thenReturn(device);
            when(device.getProfile()).thenReturn(profile); when(profile.getUser()).thenReturn(keyOwner); when(keyOwner.getId()).thenReturn(2L);
            when(envelope.getOwnerSigningKey()).thenReturn(signingKey); when(envelope.getEnvelope()).thenReturn(envelopeBytes);
            when(envelope.getOwnerSignature()).thenReturn(new byte[]{7}); when(signingKey.getKeyId()).thenReturn(new byte[]{8});
            when(signingKey.getPublicKey()).thenReturn(new byte[]{9});
            when(recipientKey.getKeyId()).thenReturn(new byte[]{10});
            when(parser.parse(envelopeBytes)).thenReturn(new LockboxShareEnvelopeParser.ParsedContext(
                    shareUuid, UUID.randomUUID(), 1L, new byte[64], UUID.randomUUID(),
                    UUID.randomUUID(), new byte[]{10}, 1, 0L));
        }

        void stubRelation() {
            when(shares.findReceivedAvailableShare(eq(shareUuid), eq(2L), eq(deviceUuid), any(), any())).thenReturn(Optional.of(share));
            when(envelopes.findByShareId(9L)).thenReturn(Optional.of(envelope));
        }
        void stubThroughSignature() throws Exception {
            stubRelation();
            when(storage.size("manifest")).thenReturn((long) manifest.length);
            when(storage.download("manifest")).thenReturn(new ByteArrayInputStream(manifest));
            when(storage.size("signature")).thenReturn((long) signature.length);
            when(storage.download("signature")).thenReturn(new ByteArrayInputStream(signature));
        }
        void stubValidArtifacts() throws Exception {
            stubThroughSignature();
            when(storage.size("container")).thenReturn(100L);
            when(storage.download("container")).thenReturn(new ByteArrayInputStream(concat(header, new byte[60])));
        }
        private static byte[] header(int size) {
            byte[] bytes = new byte[size];
            ByteBuffer.wrap(bytes, 12, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(size);
            return bytes;
        }
        private static byte[] concat(byte[] first, byte[] second) {
            byte[] result = Arrays.copyOf(first, first.length + second.length);
            System.arraycopy(second, 0, result, first.length, second.length);
            return result;
        }
    }
}
