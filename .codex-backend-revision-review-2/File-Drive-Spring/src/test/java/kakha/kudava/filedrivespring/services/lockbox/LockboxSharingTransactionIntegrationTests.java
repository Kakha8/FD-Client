package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.dto.lockbox.LockboxCreateShareRequest;
import kakha.kudava.filedrivespring.enums.DriveSpace;
import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.LockboxDevice;
import kakha.kudava.filedrivespring.model.LockboxFile;
import kakha.kudava.filedrivespring.model.LockboxFileRevision;
import kakha.kudava.filedrivespring.model.LockboxKey;
import kakha.kudava.filedrivespring.model.LockboxProfile;
import kakha.kudava.filedrivespring.model.LockboxShare;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import kakha.kudava.filedrivespring.repository.LockboxDeviceRepository;
import kakha.kudava.filedrivespring.repository.LockboxFileRepository;
import kakha.kudava.filedrivespring.repository.LockboxFileRevisionRepository;
import kakha.kudava.filedrivespring.repository.LockboxKeyRepository;
import kakha.kudava.filedrivespring.repository.LockboxProfileRepository;
import kakha.kudava.filedrivespring.repository.LockboxShareEnvelopeRepository;
import kakha.kudava.filedrivespring.repository.LockboxShareRepository;
import kakha.kudava.filedrivespring.repository.UserRepository;
import kakha.kudava.filedrivespring.services.ResourceAccessService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

@DataJpaTest
@Import({LockboxSharingService.class, LockboxShareEnvelopeParser.class})
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class LockboxSharingTransactionIntegrationTests {
    private static final UUID FILE_UUID = UUID.fromString("01234567-89ab-4cde-8fab-0123456789ab");
    private static final UUID SHARE_UUID = UUID.fromString("11223344-5566-4788-99aa-bbccddeeff00");
    private static final byte[] HASH = filled(64, (byte) 3);
    private static final byte[] RECIPIENT_KEY_ID = filled(32, (byte) 6);
    private static final byte[] SIGNING_KEY_ID = filled(32, (byte) 7);
    private static final byte[] SIGNATURE = filled(4_627, (byte) 9);

    @Autowired UserRepository users;
    @Autowired FileMetaDataRepository metadataRepository;
    @Autowired LockboxProfileRepository profiles;
    @Autowired LockboxDeviceRepository devices;
    @Autowired LockboxKeyRepository keys;
    @Autowired LockboxFileRepository files;
    @Autowired LockboxFileRevisionRepository revisions;
    @Autowired LockboxShareRepository shares;
    @MockitoSpyBean LockboxShareEnvelopeRepository envelopes;
    @Autowired LockboxSharingService service;
    @Autowired PlatformTransactionManager transactionManager;
    @MockitoBean ResourceAccessService access;
    @MockitoBean LockboxSignatureVerifier verifier;
    @MockitoBean LockboxObjectStorage objectStorage;

    User owner;
    User recipient;
    LockboxFile file;
    LockboxDevice ownerDevice;
    LockboxDevice recipientDevice;

    @BeforeEach
    void setUp() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> setUpData());
    }

    private void setUpData() {
        envelopes.deleteAllInBatch();
        shares.deleteAllInBatch();
        revisions.deleteAllInBatch();
        files.deleteAllInBatch();
        keys.deleteAllInBatch();
        devices.deleteAllInBatch();
        profiles.deleteAllInBatch();
        metadataRepository.deleteAllInBatch();
        users.deleteAllInBatch();

        owner = saveUser("owner", UUID.fromString("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"));
        recipient = saveUser("recipient", UUID.fromString("12345678-1234-4abc-9def-123456789abc"));
        LockboxProfile ownerProfile = profiles.saveAndFlush(new LockboxProfile(owner));
        LockboxProfile recipientProfile = profiles.saveAndFlush(new LockboxProfile(recipient));
        ownerDevice = devices.saveAndFlush(new LockboxDevice(ownerProfile, UUID.randomUUID(), filled(32, (byte) 1), "owner device"));
        recipientDevice = devices.saveAndFlush(new LockboxDevice(recipientProfile, UUID.randomUUID(), filled(32, (byte) 1), "recipient device"));
        keys.saveAndFlush(new LockboxKey(
                recipientDevice, LockboxKey.Role.ENCRYPTION, LockboxKey.Algorithm.ML_KEM_1024,
                RECIPIENT_KEY_ID, new byte[]{1}
        ));
        keys.saveAndFlush(new LockboxKey(
                ownerDevice, LockboxKey.Role.SIGNING, LockboxKey.Algorithm.ML_DSA_87,
                SIGNING_KEY_ID, new byte[]{2}
        ));

        FileMetaData metadata = new FileMetaData();
        metadata.setObjectKey("container-object");
        metadata.setFileName("file.lockbox");
        metadata.setObjectType("application/octet-stream");
        metadata.setChecksum("checksum");
        metadata.setSize(1L);
        metadata.setOwner(owner);
        metadata.setDriveSpace(DriveSpace.LOCKBOX);
        metadata = metadataRepository.saveAndFlush(metadata);
        file = files.saveAndFlush(new LockboxFile(metadata, ownerProfile, FILE_UUID, 7));
        revisions.saveAndFlush(new LockboxFileRevision(file,7,3,1,1,HASH,RECIPIENT_KEY_ID,
                SIGNING_KEY_ID,ownerDevice.getDeviceUuid(),1,1,"container","manifest","signature"));
        when(access.currentUser()).thenReturn(owner);
    }

    @Test
    void validRequestCommitsShareAndEnvelopeRows() {
        var response = service.createShare(request());
        assertEquals(SHARE_UUID.toString(), response.shareId());
        assertEquals(1, shares.count());
        assertEquals(1, envelopes.count());
    }

    @Test
    void envelopePersistenceFailureRollsBackInsertedShare() {
        doThrow(new DataIntegrityViolationException("forced envelope failure"))
                .when(envelopes).saveAndFlush(any());
        assertThrows(LockboxApiException.class, () -> service.createShare(request()));
        assertEquals(0, shares.count());
        assertEquals(0, envelopes.count());
    }

    @Test
    void receivedQueriesEnforceRecipientAndTargetDevice() {
        service.createShare(request());
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            Instant now = Instant.now();
            var available = shares.findReceivedAvailableShares(
                    recipient.getId(), recipientDevice.getDeviceUuid(), LockboxShare.Status.ACTIVE,
                    now, PageRequest.of(0, 100));
            assertEquals(List.of(SHARE_UUID),
                    available.stream().map(LockboxShare::getShareUuid).toList());
            assertTrue(shares.findReceivedAvailableShare(
                    SHARE_UUID, owner.getId(), recipientDevice.getDeviceUuid(),
                    LockboxShare.Status.ACTIVE, now).isEmpty());
            assertTrue(shares.findReceivedAvailableShare(
                    SHARE_UUID, recipient.getId(), ownerDevice.getDeviceUuid(),
                    LockboxShare.Status.ACTIVE, now).isEmpty());
            LockboxShare share = available.getFirst();
            share.revoke();
            shares.saveAndFlush(share);
            assertTrue(shares.findReceivedAvailableShare(
                    SHARE_UUID, recipient.getId(), recipientDevice.getDeviceUuid(),
                    LockboxShare.Status.ACTIVE, now).isEmpty());
        });
    }

    @Test
    void installationHandleLookupIsProfileScopedAndNotGloballyUnique() {
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            byte[] handle = filled(32, (byte) 1);
            LockboxProfile ownerProfile = profiles.findByUserId(owner.getId()).orElseThrow();
            LockboxProfile recipientProfile = profiles.findByUserId(recipient.getId()).orElseThrow();
            assertTrue(devices.findByProfileIdAndInstallationHandle(ownerProfile.getId(), handle).isPresent());
            assertTrue(devices.findByProfileIdAndInstallationHandle(recipientProfile.getId(), handle).isPresent());
            assertTrue(devices.findByProfileIdAndInstallationHandle(Long.MAX_VALUE, handle).isEmpty());
        });
    }

    private LockboxCreateShareRequest request() {
        return new LockboxCreateShareRequest(
                file.getId(),
                Base64.getEncoder().encodeToString(packageBytes()),
                Base64.getEncoder().encodeToString(SIGNING_KEY_ID),
                Base64.getEncoder().encodeToString(SIGNATURE)
        );
    }

    private byte[] packageBytes() {
        byte[] value = new byte[1_858];
        System.arraycopy("FDSHENV1".getBytes(java.nio.charset.StandardCharsets.US_ASCII), 0, value, 0, 8);
        putShort(value, 8, 1); putShort(value, 10, 1);
        putUuid(value, 12, SHARE_UUID); putUuid(value, 28, FILE_UUID);
        putLong(value, 44, 7); System.arraycopy(HASH, 0, value, 52, HASH.length);
        putUuid(value, 116, owner.getPublicUuid()); putUuid(value, 132, recipient.getPublicUuid());
        System.arraycopy(RECIPIENT_KEY_ID, 0, value, 148, RECIPIENT_KEY_ID.length);
        putShort(value, 180, 1); putLong(value, 182, 0); putInt(value, 234, 1_568); putInt(value, 238, 48);
        Arrays.fill(value, 242, value.length, (byte) 11);
        return value;
    }

    private User saveUser(String username, UUID uuid) {
        User user = new User(); user.setUsername(username); user.setPassword("password"); user.setRole(User.Role.USER); user.setPublicUuid(uuid);
        return users.saveAndFlush(user);
    }
    private static byte[] filled(int size, byte value) { byte[] result = new byte[size]; Arrays.fill(result, value); return result; }
    private static void putUuid(byte[] bytes, int offset, UUID uuid) { ByteBuffer.wrap(bytes, offset, 16).order(ByteOrder.BIG_ENDIAN).putLong(uuid.getMostSignificantBits()).putLong(uuid.getLeastSignificantBits()); }
    private static void putShort(byte[] bytes, int offset, int value) { ByteBuffer.wrap(bytes, offset, 2).order(ByteOrder.LITTLE_ENDIAN).putShort((short) value); }
    private static void putInt(byte[] bytes, int offset, int value) { ByteBuffer.wrap(bytes, offset, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(value); }
    private static void putLong(byte[] bytes, int offset, long value) { ByteBuffer.wrap(bytes, offset, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(value); }
}
