package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.dto.lockbox.LockboxCreateShareRequest;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxShareResponse;
import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.LockboxDevice;
import kakha.kudava.filedrivespring.model.LockboxFile;
import kakha.kudava.filedrivespring.model.LockboxFileRevision;
import kakha.kudava.filedrivespring.model.LockboxKey;
import kakha.kudava.filedrivespring.model.LockboxProfile;
import kakha.kudava.filedrivespring.model.LockboxShare;
import kakha.kudava.filedrivespring.model.LockboxShareEnvelope;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.LockboxFileRepository;
import kakha.kudava.filedrivespring.repository.LockboxFileRevisionRepository;
import kakha.kudava.filedrivespring.repository.LockboxDeviceRepository;
import kakha.kudava.filedrivespring.repository.LockboxKeyRepository;
import kakha.kudava.filedrivespring.repository.LockboxShareEnvelopeRepository;
import kakha.kudava.filedrivespring.repository.LockboxShareRepository;
import kakha.kudava.filedrivespring.repository.UserRepository;
import kakha.kudava.filedrivespring.services.ResourceAccessService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class LockboxSharingServiceCreateShareTests {
    @Test
    void validRequestVerifiesExactBytesAndPersistsActiveShareAndEnvelope() {
        Fixture fixture = new Fixture();
        long expiry = Instant.now().plusSeconds(3_600).getEpochSecond();
        byte[] packageBytes = fixture.packageBytes(expiry);

        var response = fixture.service.createShare(fixture.request(packageBytes));

        ArgumentCaptor<byte[]> publicKey = ArgumentCaptor.forClass(byte[].class);
        ArgumentCaptor<byte[]> message = ArgumentCaptor.forClass(byte[].class);
        ArgumentCaptor<byte[]> capturedSignature = ArgumentCaptor.forClass(byte[].class);
        verify(fixture.verifier).verify(
                publicKey.capture(),
                message.capture(),
                capturedSignature.capture()
        );
        assertArrayEquals(fixture.signingPublicKey, publicKey.getValue());
        assertArrayEquals(LockboxSharingService.signatureMessage(packageBytes), message.getValue());
        assertArrayEquals(fixture.signature, capturedSignature.getValue());
        assertEquals(25 + 1_858, message.getValue().length);

        ArgumentCaptor<LockboxShare> shareCaptor = ArgumentCaptor.forClass(LockboxShare.class);
        verify(fixture.shares).save(shareCaptor.capture());
        LockboxShare share = shareCaptor.getValue();
        assertEquals(Fixture.SHARE_UUID, share.getShareUuid());
        assertEquals(Instant.ofEpochSecond(expiry), share.getExpiresAt());
        assertEquals(LockboxShare.Status.ACTIVE, share.getStatus());

        ArgumentCaptor<LockboxShareEnvelope> envelopeCaptor =
                ArgumentCaptor.forClass(LockboxShareEnvelope.class);
        verify(fixture.envelopes).saveAndFlush(envelopeCaptor.capture());
        assertArrayEquals(packageBytes, envelopeCaptor.getValue().getEnvelope());
        assertArrayEquals(fixture.signature, envelopeCaptor.getValue().getOwnerSignature());
        assertEquals(Fixture.SHARE_UUID.toString(), response.shareId());
        assertEquals("ACTIVE", response.status());
    }

    @Test
    void nullOrMissingFileIdIsBadRequestWithoutPersistence() {
        Fixture fixture = new Fixture();
        assertError(fixture, null, "INVALID_LOCKBOX_SHARE", HttpStatus.BAD_REQUEST);
        assertError(
                fixture,
                new LockboxCreateShareRequest(null, "x", "x", "x"),
                "INVALID_LOCKBOX_SHARE",
                HttpStatus.BAD_REQUEST
        );
    }

    @Test
    void inaccessibleDeletedAndPermanentlyDeletedFilesAreNotFound() {
        Fixture inaccessible = new Fixture();
        when(inaccessible.files.findByIdAndProfileUserId(10L, 1L)).thenReturn(Optional.empty());
        assertError(inaccessible, inaccessible.request(), "LOCKBOX_FILE_NOT_FOUND", HttpStatus.NOT_FOUND);

        Fixture deleted = new Fixture();
        when(deleted.metadata.isDeleted()).thenReturn(true);
        assertError(deleted, deleted.request(), "LOCKBOX_FILE_NOT_FOUND", HttpStatus.NOT_FOUND);

        Fixture permanent = new Fixture();
        when(permanent.metadata.isPermanentlyDeleted()).thenReturn(true);
        assertError(permanent, permanent.request(), "LOCKBOX_FILE_NOT_FOUND", HttpStatus.NOT_FOUND);
    }

    @Test
    void malformedEnvelopeInputsAreBadRequest() {
        Fixture invalidBase64 = new Fixture();
        String bad = "!".repeat(Base64.getEncoder().encodeToString(new byte[1_858]).length());
        assertError(invalidBase64, invalidBase64.requestWithEnvelope(bad), "INVALID_LOCKBOX_SHARE", HttpStatus.BAD_REQUEST);

        Fixture wrongLength = new Fixture();
        assertError(
                wrongLength,
                wrongLength.requestWithEnvelope(Base64.getEncoder().encodeToString(new byte[1_857])),
                "INVALID_LOCKBOX_SHARE",
                HttpStatus.BAD_REQUEST
        );
    }

    @Test
    void publicFileBindingsMustMatch() {
        assertBindingMismatch(116, UUID.randomUUID());
        assertBindingMismatch(28, UUID.randomUUID());

        Fixture revision = new Fixture();
        byte[] packageBytes = revision.packageBytes(0);
        putLong(packageBytes, 44, 8L);
        assertError(revision, revision.request(packageBytes), "INVALID_LOCKBOX_SHARE", HttpStatus.BAD_REQUEST);

        Fixture hash = new Fixture();
        packageBytes = hash.packageBytes(0);
        packageBytes[52] ^= 1;
        assertError(hash, hash.request(packageBytes), "INVALID_LOCKBOX_SHARE", HttpStatus.BAD_REQUEST);
    }

    @Test
    void recipientAndRecipientKeyFailuresUseStableNotFoundPolicy() {
        Fixture missingRecipient = new Fixture();
        when(missingRecipient.users.findByPublicUuid(Fixture.RECIPIENT_UUID)).thenReturn(Optional.empty());
        assertError(missingRecipient, missingRecipient.request(), "LOCKBOX_RECIPIENT_UNAVAILABLE", HttpStatus.NOT_FOUND);

        Fixture missingKey = new Fixture();
        when(missingKey.keys.findByKeyId(missingKey.recipientKeyId)).thenReturn(Optional.empty());
        assertError(missingKey, missingKey.request(), "LOCKBOX_RECIPIENT_UNAVAILABLE", HttpStatus.NOT_FOUND);

        assertRecipientKeyInvalid(KeyFailure.OWNER);
        assertRecipientKeyInvalid(KeyFailure.DEVICE);
        assertRecipientKeyInvalid(KeyFailure.STATUS);
        assertRecipientKeyInvalid(KeyFailure.ROLE);
        assertRecipientKeyInvalid(KeyFailure.ALGORITHM);
    }

    @Test
    void signingKeyAndSigningInputFailuresAreStableBadRequests() {
        Fixture missing = new Fixture();
        when(missing.keys.findByKeyId(missing.signingKeyId)).thenReturn(Optional.empty());
        assertError(missing, missing.request(), "INVALID_LOCKBOX_SHARE", HttpStatus.BAD_REQUEST);

        assertSigningKeyInvalid(KeyFailure.OWNER);
        assertSigningKeyInvalid(KeyFailure.DEVICE);
        assertSigningKeyInvalid(KeyFailure.STATUS);
        assertSigningKeyInvalid(KeyFailure.ROLE);
        assertSigningKeyInvalid(KeyFailure.ALGORITHM);

        Fixture badId = new Fixture();
        String invalidId = "!".repeat(Base64.getEncoder().encodeToString(new byte[32]).length());
        assertError(
                badId,
                new LockboxCreateShareRequest(10L, badId.request().envelope(), invalidId, badId.request().ownerSignature()),
                "INVALID_LOCKBOX_SHARE",
                HttpStatus.BAD_REQUEST
        );

        Fixture badSignature = new Fixture();
        String invalidSignature = "!".repeat(Base64.getEncoder().encodeToString(new byte[4_627]).length());
        assertError(
                badSignature,
                new LockboxCreateShareRequest(10L, badSignature.request().envelope(), badSignature.request().ownerSigningKeyId(), invalidSignature),
                "INVALID_LOCKBOX_SHARE",
                HttpStatus.BAD_REQUEST
        );
    }

    @Test
    void signatureRejectionAndTamperedPackageDoNotPersist() {
        Fixture rejected = new Fixture();
        doThrow(new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid"))
                .when(rejected.verifier).verify(any(), any(), any());
        assertError(rejected, rejected.request(), "INVALID_LOCKBOX_SHARE", HttpStatus.BAD_REQUEST);

        Fixture tampered = new Fixture();
        byte[] original = tampered.packageBytes(0);
        byte[] signedMessage = LockboxSharingService.signatureMessage(original);
        doAnswer(invocation -> {
            byte[] actual = invocation.getArgument(1);
            if (!Arrays.equals(actual, signedMessage)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "invalid");
            }
            return null;
        }).when(tampered.verifier).verify(any(), any(), any());
        byte[] modified = original.clone();
        modified[242] ^= 1;
        assertError(tampered, tampered.request(modified), "INVALID_LOCKBOX_SHARE", HttpStatus.BAD_REQUEST);
    }

    @Test
    void invalidExpiryAndDuplicateChecksDoNotPersist() {
        Fixture past = new Fixture();
        assertError(past, past.request(past.packageBytes(1)), "INVALID_LOCKBOX_SHARE", HttpStatus.BAD_REQUEST);

        Fixture current = new Fixture();
        assertError(
                current,
                current.request(current.packageBytes(Instant.now().getEpochSecond())),
                "INVALID_LOCKBOX_SHARE",
                HttpStatus.BAD_REQUEST
        );

        Fixture overflow = new Fixture();
        assertError(overflow, overflow.request(overflow.packageBytes(Long.MAX_VALUE)), "INVALID_LOCKBOX_SHARE", HttpStatus.BAD_REQUEST);

        Fixture duplicateId = new Fixture();
        when(duplicateId.shares.existsByShareUuid(Fixture.SHARE_UUID)).thenReturn(true);
        assertError(duplicateId, duplicateId.request(), "LOCKBOX_SHARE_ID_EXISTS", HttpStatus.CONFLICT);

        Fixture duplicateRecipient = new Fixture();
        when(duplicateRecipient.shares.existsByRevisionIdAndTargetDeviceId(any(), any()))
                .thenReturn(true);
        assertError(duplicateRecipient, duplicateRecipient.request(), "LOCKBOX_SHARE_ALREADY_EXISTS", HttpStatus.CONFLICT);
    }

    @Test
    void selfShareTargetsAnotherOwnedDeviceAndRejectsSigningDevice() {
        Fixture allowed = new Fixture();
        UUID signingDeviceId = UUID.randomUUID();
        UUID targetDeviceId = UUID.randomUUID();
        when(allowed.users.findByPublicUuid(Fixture.OWNER_UUID)).thenReturn(Optional.of(allowed.owner));
        when(allowed.recipientKey.getDevice().getProfile().getUser()).thenReturn(allowed.owner);
        when(allowed.signingKey.getDevice().getDeviceUuid()).thenReturn(signingDeviceId);
        when(allowed.recipientKey.getDevice().getDeviceUuid()).thenReturn(targetDeviceId);
        byte[] selfEnvelope = allowed.packageBytes(0);
        putUuid(selfEnvelope, 132, Fixture.OWNER_UUID);

        LockboxShareResponse response = allowed.service.createShare(allowed.request(selfEnvelope));

        assertEquals(Fixture.SHARE_UUID.toString(), response.shareId());
        ArgumentCaptor<LockboxShare> share = ArgumentCaptor.forClass(LockboxShare.class);
        verify(allowed.shares).save(share.capture());
        assertSame(allowed.owner, share.getValue().getRecipient());
        assertSame(allowed.recipientKey.getDevice(), share.getValue().getTargetDevice());

        Fixture rejected = new Fixture();
        when(rejected.users.findByPublicUuid(Fixture.OWNER_UUID)).thenReturn(Optional.of(rejected.owner));
        when(rejected.recipientKey.getDevice().getProfile().getUser()).thenReturn(rejected.owner);
        when(rejected.signingKey.getDevice().getDeviceUuid()).thenReturn(signingDeviceId);
        when(rejected.recipientKey.getDevice().getDeviceUuid()).thenReturn(signingDeviceId);
        selfEnvelope = rejected.packageBytes(0);
        putUuid(selfEnvelope, 132, Fixture.OWNER_UUID);

        assertError(rejected, rejected.request(selfEnvelope),
                "LOCKBOX_SELF_SHARE_SAME_DEVICE", HttpStatus.BAD_REQUEST);
    }

    @Test
    void dataIntegrityViolationMapsToConflict() {
        Fixture fixture = new Fixture();
        when(fixture.envelopes.saveAndFlush(any())).thenThrow(new DataIntegrityViolationException("constraint"));
        LockboxApiException error = assertThrows(LockboxApiException.class, () -> fixture.service.createShare(fixture.request()));
        assertEquals("LOCKBOX_SHARE_CONFLICT", error.getCode());
        assertEquals(HttpStatus.CONFLICT, error.getStatus());
        verify(fixture.shares).save(any());
    }

    private static void assertBindingMismatch(int offset, UUID value) {
        Fixture fixture = new Fixture();
        byte[] packageBytes = fixture.packageBytes(0);
        putUuid(packageBytes, offset, value);
        assertError(fixture, fixture.request(packageBytes), "INVALID_LOCKBOX_SHARE", HttpStatus.BAD_REQUEST);
    }

    private static void assertRecipientKeyInvalid(KeyFailure failure) {
        Fixture fixture = new Fixture();
        fixture.applyFailure(fixture.recipientKey, failure, fixture.otherUser);
        assertError(fixture, fixture.request(), "LOCKBOX_RECIPIENT_UNAVAILABLE", HttpStatus.NOT_FOUND);
    }

    private static void assertSigningKeyInvalid(KeyFailure failure) {
        Fixture fixture = new Fixture();
        fixture.applyFailure(fixture.signingKey, failure, fixture.otherUser);
        assertError(fixture, fixture.request(), "INVALID_LOCKBOX_SHARE", HttpStatus.BAD_REQUEST);
    }

    private static void assertError(Fixture fixture, LockboxCreateShareRequest request, String code, HttpStatus status) {
        LockboxApiException error = assertThrows(LockboxApiException.class, () -> fixture.service.createShare(request));
        assertEquals(code, error.getCode());
        assertEquals(status, error.getStatus());
        verify(fixture.shares, never()).save(any());
        verifyNoInteractions(fixture.envelopes);
    }

    private enum KeyFailure { OWNER, DEVICE, STATUS, ROLE, ALGORITHM }

    private static final class Fixture {
        static final UUID SHARE_UUID = UUID.fromString("11223344-5566-4788-99aa-bbccddeeff00");
        static final UUID FILE_UUID = UUID.fromString("01234567-89ab-4cde-8fab-0123456789ab");
        static final UUID OWNER_UUID = UUID.fromString("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        static final UUID RECIPIENT_UUID = UUID.fromString("12345678-1234-4abc-9def-123456789abc");

        final UserRepository users = mock(UserRepository.class);
        final LockboxKeyRepository keys = mock(LockboxKeyRepository.class);
        final ResourceAccessService access = mock(ResourceAccessService.class);
        final LockboxFileRepository files = mock(LockboxFileRepository.class);
        final LockboxFileRevisionRepository revisions = mock(LockboxFileRevisionRepository.class);
        final LockboxShareRepository shares = mock(LockboxShareRepository.class);
        final LockboxShareEnvelopeRepository envelopes = mock(LockboxShareEnvelopeRepository.class);
        final LockboxSignatureVerifier verifier = mock(LockboxSignatureVerifier.class);
        final LockboxObjectStorage objectStorage = mock(LockboxObjectStorage.class);
        final LockboxDeviceRepository devices = mock(LockboxDeviceRepository.class);
        final LockboxSharingService service = new LockboxSharingService(
                users, keys, access, files, revisions, shares, envelopes,
                new LockboxShareEnvelopeParser(), verifier, objectStorage, devices
        );
        final User owner = user(1L, "owner", OWNER_UUID);
        final User recipient = user(2L, "recipient", RECIPIENT_UUID);
        final User otherUser = user(3L, "other", UUID.randomUUID());
        final LockboxFile file = mock(LockboxFile.class);
        final LockboxFileRevision revision = mock(LockboxFileRevision.class);
        final FileMetaData metadata = mock(FileMetaData.class);
        final byte[] hash = filled(64, (byte) 3);
        final byte[] recipientKeyId = filled(32, (byte) 6);
        final byte[] signingKeyId = filled(32, (byte) 7);
        final byte[] signingPublicKey = filled(2_592, (byte) 8);
        final byte[] signature = filled(4_627, (byte) 9);
        final LockboxKey recipientKey = key(recipient, LockboxKey.Role.ENCRYPTION, LockboxKey.Algorithm.ML_KEM_1024, recipientKeyId, new byte[]{1});
        final LockboxKey signingKey = key(owner, LockboxKey.Role.SIGNING, LockboxKey.Algorithm.ML_DSA_87, signingKeyId, signingPublicKey);

        Fixture() {
            when(access.currentUser()).thenReturn(owner);
            when(files.findByIdAndProfileUserId(10L, 1L)).thenReturn(Optional.of(file));
            when(file.getId()).thenReturn(10L);
            when(file.getFile()).thenReturn(metadata);
            when(file.getClientFileId()).thenReturn(FILE_UUID);
            when(file.getCurrentRevision()).thenReturn(7L);
            when(revisions.findByLockboxFileIdAndRevision(10L,7L)).thenReturn(Optional.of(revision));
            when(revision.getRevision()).thenReturn(7L); when(revision.getContainerHash()).thenReturn(hash.clone());
            when(users.findByPublicUuid(RECIPIENT_UUID)).thenReturn(Optional.of(recipient));
            when(keys.findByKeyId(argThat(value -> Arrays.equals(value, recipientKeyId))))
                    .thenReturn(Optional.of(recipientKey));
            when(keys.findByKeyId(argThat(value -> Arrays.equals(value, signingKeyId))))
                    .thenReturn(Optional.of(signingKey));
            when(shares.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
            when(envelopes.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
        }

        LockboxCreateShareRequest request() { return request(packageBytes(0)); }
        LockboxCreateShareRequest request(byte[] packageBytes) {
            return new LockboxCreateShareRequest(
                    10L,
                    Base64.getEncoder().encodeToString(packageBytes),
                    Base64.getEncoder().encodeToString(signingKeyId),
                    Base64.getEncoder().encodeToString(signature)
            );
        }
        LockboxCreateShareRequest requestWithEnvelope(String envelope) {
            return new LockboxCreateShareRequest(
                    10L,
                    envelope,
                    Base64.getEncoder().encodeToString(signingKeyId),
                    Base64.getEncoder().encodeToString(signature)
            );
        }
        byte[] packageBytes(long expiry) {
            byte[] value = new byte[1_858];
            System.arraycopy("FDSHENV1".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 0, value, 0, 8);
            putShort(value, 8, 1); putShort(value, 10, 1);
            putUuid(value, 12, SHARE_UUID); putUuid(value, 28, FILE_UUID);
            putLong(value, 44, 7); Arrays.fill(value, 52, 116, (byte) 3);
            putUuid(value, 116, OWNER_UUID); putUuid(value, 132, RECIPIENT_UUID);
            Arrays.fill(value, 148, 180, (byte) 6); putShort(value, 180, 1);
            putLong(value, 182, expiry); putInt(value, 234, 1_568); putInt(value, 238, 48);
            Arrays.fill(value, 242, value.length, (byte) 11);
            return value;
        }
        void applyFailure(LockboxKey key, KeyFailure failure, User wrongOwner) {
            if (failure == KeyFailure.OWNER) {
                LockboxProfile profile = mock(LockboxProfile.class);
                when(profile.getUser()).thenReturn(wrongOwner);
                when(key.getDevice().getProfile()).thenReturn(profile);
            } else if (failure == KeyFailure.DEVICE) {
                when(key.getDevice().getStatus()).thenReturn(LockboxDevice.Status.REVOKED);
            } else if (failure == KeyFailure.STATUS) {
                when(key.getStatus()).thenReturn(LockboxKey.Status.REVOKED);
            } else if (failure == KeyFailure.ROLE) {
                LockboxKey.Role wrong = key == recipientKey ? LockboxKey.Role.SIGNING : LockboxKey.Role.ENCRYPTION;
                when(key.getRole()).thenReturn(wrong);
            } else {
                LockboxKey.Algorithm wrong = key == recipientKey ? LockboxKey.Algorithm.ML_DSA_87 : LockboxKey.Algorithm.ML_KEM_1024;
                when(key.getAlgorithm()).thenReturn(wrong);
            }
        }
    }

    private static User user(long id, String username, UUID uuid) {
        User user = new User(); user.setId(id); user.setUsername(username); user.setPublicUuid(uuid); return user;
    }
    private static LockboxKey key(User user, LockboxKey.Role role, LockboxKey.Algorithm algorithm, byte[] id, byte[] publicKey) {
        LockboxKey key = mock(LockboxKey.class); LockboxDevice device = mock(LockboxDevice.class); LockboxProfile profile = mock(LockboxProfile.class);
        when(key.getDevice()).thenReturn(device); when(device.getProfile()).thenReturn(profile); when(profile.getUser()).thenReturn(user);
        when(device.getStatus()).thenReturn(LockboxDevice.Status.ACTIVE); when(key.getRole()).thenReturn(role); when(key.getAlgorithm()).thenReturn(algorithm);
        when(key.getStatus()).thenReturn(LockboxKey.Status.ACTIVE); when(key.getKeyId()).thenReturn(id.clone()); when(key.getPublicKey()).thenReturn(publicKey);
        return key;
    }
    private static byte[] filled(int size, byte value) { byte[] result = new byte[size]; Arrays.fill(result, value); return result; }
    private static void putUuid(byte[] bytes, int offset, UUID uuid) { ByteBuffer.wrap(bytes, offset, 16).order(ByteOrder.BIG_ENDIAN).putLong(uuid.getMostSignificantBits()).putLong(uuid.getLeastSignificantBits()); }
    private static void putShort(byte[] bytes, int offset, int value) { ByteBuffer.wrap(bytes, offset, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((short) value); }
    private static void putInt(byte[] bytes, int offset, int value) { ByteBuffer.wrap(bytes, offset, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(value); }
    private static void putLong(byte[] bytes, int offset, long value) { ByteBuffer.wrap(bytes, offset, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(value); }
}
