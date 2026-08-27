package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.dto.lockbox.*;
import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import kakha.kudava.filedrivespring.model.*;
import kakha.kudava.filedrivespring.repository.*;
import kakha.kudava.filedrivespring.services.ResourceAccessService;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class LockboxInstallationHandleTests {

    @Test
    void transcriptV2HasExactLayoutAndHandleOffset() {
        UUID enrollment = UUID.fromString("00112233-4455-4677-8899-aabbccddeeff");
        UUID device = UUID.fromString("ffeeddcc-bbaa-4988-8776-554433221100");
        byte[] challenge = filled(32, (byte) 1);
        byte[] handle = filled(32, (byte) 2);
        byte[] encryptionId = filled(32, (byte) 3);
        byte[] encryptionKey = filled(1_568, (byte) 4);
        byte[] signingId = filled(32, (byte) 5);
        byte[] signingKey = filled(2_592, (byte) 6);
        Instant expiry = Instant.ofEpochMilli(0x0102030405060708L);

        byte[] encoded = new LockboxEnrollmentTranscript().encode(
                enrollment, challenge, expiry, device, handle, " workstation ",
                encryptionId, encryptionKey, signingId, signingKey);

        byte[] domain = "FD-LOCKBOX-DEVICE-ENROLLMENT-V2\0"
                .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        assertArrayEquals(domain, Arrays.copyOfRange(encoded, 0, domain.length));
        int handleOffset = domain.length + 16 + 32 + 8 + 16;
        assertArrayEquals(handle, Arrays.copyOfRange(encoded, handleOffset, handleOffset + 32));
        assertEquals(11, ByteBuffer.wrap(encoded, handleOffset + 32, 2)
                .order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xffff);
        assertEquals(domain.length + 16 + 32 + 8 + 16 + 32 + 2 + 11
                + 2 + 32 + 4 + 1_568 + 2 + 32 + 4 + 2_592, encoded.length);
    }

    @Test
    void beginRejectsInvalidCanonicalHandles() {
        Fixture fixture = new Fixture();
        for (int length : new int[]{0, 31, 33}) {
            LockboxApiException error = assertThrows(LockboxApiException.class,
                    () -> fixture.service.beginEnrollment(new LockboxEnrollmentBeginRequest(
                            fixture.deviceId, Base64.getEncoder().encodeToString(new byte[length]), "device")));
            assertEquals(HttpStatus.BAD_REQUEST, error.getStatus());
        }
        assertEquals(HttpStatus.BAD_REQUEST, assertThrows(LockboxApiException.class,
                () -> fixture.service.beginEnrollment(new LockboxEnrollmentBeginRequest(
                        fixture.deviceId, "!", "device"))).getStatus());
        assertEquals(HttpStatus.BAD_REQUEST, assertThrows(LockboxApiException.class,
                () -> fixture.service.beginEnrollment(new LockboxEnrollmentBeginRequest(
                        fixture.deviceId, Base64.getEncoder().withoutPadding().encodeToString(new byte[32]), "device")))
                .getStatus());
    }

    @Test
    void completionPersistsHandleAndSignsItInTranscript() throws Exception {
        Fixture fixture = new Fixture();
        fixture.stubCompletion();

        fixture.service.completeEnrollment(fixture.enrollmentId, fixture.request(fixture.handle));

        ArgumentCaptor<LockboxDevice> device = ArgumentCaptor.forClass(LockboxDevice.class);
        verify(fixture.devices).save(device.capture());
        assertArrayEquals(fixture.handle, device.getValue().getInstallationHandle());
        ArgumentCaptor<byte[]> transcript = ArgumentCaptor.forClass(byte[].class);
        verify(fixture.verifier).verify(eq(fixture.signingPublicKey), transcript.capture(), eq(fixture.signature));
        assertTrue(indexOf(transcript.getValue(), fixture.handle) >= 0);
    }

    @Test
    void changedOrMismatchedHandleIsRejectedBeforeSignatureVerification() throws Exception {
        Fixture fixture = new Fixture();
        fixture.stubCompletion();
        byte[] changed = fixture.handle.clone(); changed[0] ^= 1;

        LockboxApiException error = assertThrows(LockboxApiException.class,
                () -> fixture.service.completeEnrollment(fixture.enrollmentId, fixture.request(changed)));
        assertEquals(HttpStatus.BAD_REQUEST, error.getStatus());
        verifyNoInteractions(fixture.verifier);
        verify(fixture.devices, never()).save(any());
    }

    @Test
    void sameProfileHandleConflictsButDifferentHandleCanBegin() {
        Fixture conflict = new Fixture();
        when(conflict.profiles.findByUserId(1L)).thenReturn(Optional.of(conflict.profile));
        when(conflict.devices.findByProfileIdAndInstallationHandle(
                eq(10L), argThat(value -> Arrays.equals(value, conflict.handle))))
                .thenReturn(Optional.of(mock(LockboxDevice.class)));
        LockboxApiException error = assertThrows(LockboxApiException.class,
                () -> conflict.service.beginEnrollment(conflict.beginRequest(conflict.handle)));
        assertEquals(HttpStatus.CONFLICT, error.getStatus());

        Fixture allowed = new Fixture();
        when(allowed.profiles.findByUserId(1L)).thenReturn(Optional.of(allowed.profile));
        when(allowed.devices.findByProfileIdAndInstallationHandle(eq(10L), any(byte[].class)))
                .thenReturn(Optional.empty());
        when(allowed.challenges.saveAndFlush(any())).thenAnswer(invocation -> invocation.getArgument(0));
        assertNotNull(allowed.service.beginEnrollment(allowed.beginRequest(filled(32, (byte) 12))));
    }

    @Test
    void deviceDefensivelyCopiesInstallationHandle() {
        byte[] handle = filled(32, (byte) 7);
        LockboxDevice device = new LockboxDevice(mock(LockboxProfile.class), UUID.randomUUID(), handle, "device");
        handle[0] = 9;
        assertEquals(7, device.getInstallationHandle()[0]);
        byte[] returned = device.getInstallationHandle(); returned[1] = 9;
        assertEquals(7, device.getInstallationHandle()[1]);
    }

    private static final class Fixture {
        final LockboxEnrollmentChallengeRepository challenges = mock(LockboxEnrollmentChallengeRepository.class);
        final LockboxProfileRepository profiles = mock(LockboxProfileRepository.class);
        final ResourceAccessService access = mock(ResourceAccessService.class);
        final LockboxDeviceRepository devices = mock(LockboxDeviceRepository.class);
        final LockboxKeyRepository keys = mock(LockboxKeyRepository.class);
        final LockboxEnrollmentTranscript encoder = new LockboxEnrollmentTranscript();
        final LockboxSignatureVerifier verifier = mock(LockboxSignatureVerifier.class);
        final LockboxEnrollmentService service = new LockboxEnrollmentService(
                challenges, profiles, access, devices, keys, encoder, verifier);
        final User user = user();
        final LockboxProfile profile = mock(LockboxProfile.class);
        final UUID enrollmentId = UUID.randomUUID(), deviceId = UUID.randomUUID();
        final byte[] challenge = filled(32, (byte) 1), handle = filled(32, (byte) 2);
        final byte[] encryptionPublicKey = filled(1_568, (byte) 3);
        final byte[] signingPublicKey = filled(2_592, (byte) 4);
        final byte[] encryptionId = sha3(encryptionPublicKey), signingId = sha3(signingPublicKey);
        final byte[] signature = filled(4_627, (byte) 5);
        final Instant expiry = Instant.now().plusSeconds(300);

        Fixture() {
            when(access.currentUser()).thenReturn(user); when(profile.getId()).thenReturn(10L);
            when(devices.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
            when(keys.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        }
        LockboxEnrollmentBeginRequest beginRequest(byte[] value) {
            return new LockboxEnrollmentBeginRequest(deviceId, b64(value), "device");
        }
        LockboxEnrollmentCompleteRequest request(byte[] value) {
            return new LockboxEnrollmentCompleteRequest(
                    b64(challenge), deviceId, b64(value), "device",
                    new LockboxEnrollmentCompleteRequest.PublicKeyRequest("ML_KEM_1024", b64(encryptionId), b64(encryptionPublicKey)),
                    new LockboxEnrollmentCompleteRequest.PublicKeyRequest("ML_DSA_87", b64(signingId), b64(signingPublicKey)), b64(signature));
        }
        void stubCompletion() {
            byte[] challengeHash = sha3(challenge);
            LockboxEnrollmentChallenge enrollment = new LockboxEnrollmentChallenge(
                    user, enrollmentId, challengeHash, deviceId, "device", handle, expiry);
            when(challenges.findForCompletion(enrollmentId, 1L)).thenReturn(Optional.of(enrollment));
            when(profiles.findByUserId(1L)).thenReturn(Optional.of(profile));
            when(devices.findByProfileIdAndInstallationHandle(eq(10L), any(byte[].class))).thenReturn(Optional.empty());
        }
        private static User user() { User u = new User(); u.setId(1L); u.setUsername("user"); return u; }
    }

    private static byte[] sha3(byte[] value) {
        try { return MessageDigest.getInstance("SHA3-256").digest(value); }
        catch (Exception exception) { throw new AssertionError(exception); }
    }
    private static byte[] filled(int length, byte value) { byte[] result = new byte[length]; Arrays.fill(result, value); return result; }
    private static String b64(byte[] value) { return Base64.getEncoder().encodeToString(value); }
    private static int indexOf(byte[] source, byte[] target) {
        outer: for (int i = 0; i <= source.length - target.length; i++) {
            for (int j = 0; j < target.length; j++) if (source[i + j] != target[j]) continue outer;
            return i;
        }
        return -1;
    }
}
