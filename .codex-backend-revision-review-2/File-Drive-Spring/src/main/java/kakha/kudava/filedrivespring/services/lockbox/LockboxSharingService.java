package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.dto.lockbox.*;
import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import kakha.kudava.filedrivespring.model.LockboxDevice;
import kakha.kudava.filedrivespring.model.LockboxFile;
import kakha.kudava.filedrivespring.model.LockboxFileRevision;
import kakha.kudava.filedrivespring.model.LockboxKey;
import kakha.kudava.filedrivespring.model.LockboxShare;
import kakha.kudava.filedrivespring.model.LockboxShareEnvelope;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.records.LockboxDownloadResult;
import kakha.kudava.filedrivespring.repository.LockboxFileRepository;
import kakha.kudava.filedrivespring.repository.LockboxFileRevisionRepository;
import kakha.kudava.filedrivespring.repository.LockboxDeviceRepository;
import kakha.kudava.filedrivespring.repository.LockboxKeyRepository;
import kakha.kudava.filedrivespring.repository.LockboxShareEnvelopeRepository;
import kakha.kudava.filedrivespring.repository.LockboxShareRepository;
import kakha.kudava.filedrivespring.repository.UserRepository;
import kakha.kudava.filedrivespring.services.ResourceAccessService;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.DateTimeException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Objects;

@Service
public class LockboxSharingService {
    static final byte[] GRANT_DOMAIN =
            "FD-CSE-V3-SHARE-GRANT-V1\0".getBytes(StandardCharsets.US_ASCII);

    private final UserRepository users;
    private final LockboxKeyRepository keys;
    private final ResourceAccessService access;
    private final LockboxFileRepository files;
    private final LockboxFileRevisionRepository revisions;
    private final LockboxShareRepository shares;
    private final LockboxShareEnvelopeRepository envelopes;
    private final LockboxShareEnvelopeParser parser;
    private final LockboxSignatureVerifier verifier;

    private static final int MAX_RECEIVED_SHARES = 100;
    private static final int MAX_MANIFEST_SIZE = 1_024;
    private static final int MAX_SIGNATURE_SIZE = 16 * 1_024;
    private static final int MAX_HEADER_SIZE = 1024 * 1024;

    private final LockboxObjectStorage objectStorage;
    private final LockboxDeviceRepository devices;

    public LockboxSharingService(
            UserRepository users,
            LockboxKeyRepository keys,
            ResourceAccessService access,
            LockboxFileRepository files,
            LockboxFileRevisionRepository revisions,
            LockboxShareRepository shares,
            LockboxShareEnvelopeRepository envelopes,
            LockboxShareEnvelopeParser parser,
            LockboxSignatureVerifier verifier, LockboxObjectStorage objectStorage,
            LockboxDeviceRepository devices
    ) {
        this.users = users;
        this.keys = keys;
        this.access = access;
        this.files = files;
        this.revisions = revisions;
        this.shares = shares;
        this.envelopes = envelopes;
        this.parser = parser;
        this.verifier = verifier;
        this.objectStorage = objectStorage;
        this.devices = devices;
    }

    @Transactional(readOnly = true)
    public LockboxOwnDevicesResponse ownDevices(UUID excludeDeviceId) {
        User user = access.currentUser();
        List<LockboxDevice> owned = devices.findOwnedDevices(
                user.getId(), excludeDeviceId);
        Map<Long, List<LockboxOwnDeviceKeyResponse>> keysByDevice = new LinkedHashMap<>();
        Base64.Encoder base64 = Base64.getEncoder();
        for (LockboxKey key : keys.findOwnedActiveEncryptionKeys(
                user.getId(), LockboxDevice.Status.ACTIVE,
                LockboxKey.Role.ENCRYPTION, LockboxKey.Algorithm.ML_KEM_1024,
                LockboxKey.Status.ACTIVE)) {
            keysByDevice.computeIfAbsent(key.getDevice().getId(), ignored -> new ArrayList<>())
                    .add(new LockboxOwnDeviceKeyResponse(
                            base64.encodeToString(key.getKeyId()),
                            key.getAlgorithm().name(),
                            base64.encodeToString(key.getPublicKey())));
        }
        return new LockboxOwnDevicesResponse(owned.stream()
                .map(device -> new LockboxOwnDeviceResponse(
                        device.getDeviceUuid(), device.getDisplayName(), device.getStatus().name(),
                        device.getCreatedAt(), device.getLastSeenAt(),
                        keysByDevice.getOrDefault(device.getId(), List.of())))
                .toList());
    }

    @Transactional(readOnly = true)
    public LockboxRecipientKeysResponse recipientEncryptionKeys(String username) {
        User requester = access.currentUser();
        User recipient = users.findByUsername(normalizeUsername(username))
                .orElseThrow(LockboxSharingService::recipientUnavailable);

        if (requester.getId().equals(recipient.getId())) {
            throw invalid("You cannot share a Lockbox file with yourself.");
        }

        List<LockboxKey> found =
                keys.findAllByDeviceProfileUserIdAndDeviceStatusAndRoleAndStatus(
                        recipient.getId(),
                        LockboxDevice.Status.ACTIVE,
                        LockboxKey.Role.ENCRYPTION,
                        LockboxKey.Status.ACTIVE
                );

        if (found.isEmpty() || recipient.getPublicUuid() == null) {
            throw recipientUnavailable();
        }

        Base64.Encoder base64 = Base64.getEncoder();
        List<LockboxRecipientKeyResponse> keyResponses = found.stream()
                .map(key -> new LockboxRecipientKeyResponse(
                        base64.encodeToString(key.getKeyId()),
                        key.getAlgorithm().name(),
                        base64.encodeToString(key.getPublicKey())
                ))
                .toList();

        return new LockboxRecipientKeysResponse(
                recipient.getId(),
                recipient.getPublicUuid(),
                recipient.getUsername(),
                keyResponses
        );
    }

    @Transactional
    public LockboxShareResponse createShare(LockboxCreateShareRequest request) {
        if (request == null || request.fileId() == null) {
            throw invalid("The Lockbox file ID is required.");
        }

        User owner = access.currentUser();
        LockboxFile file = files.findByIdAndProfileUserId(request.fileId(), owner.getId())
                .orElseThrow(LockboxSharingService::fileNotFound);

        if (file.getFile().isDeleted() || file.getFile().isPermanentlyDeleted()) {
            throw fileNotFound();
        }
        long requestedRevision=request.revision()==null?file.getCurrentRevision():request.revision();
        LockboxFileRevision selectedRevision=revisions.findByLockboxFileIdAndRevision(file.getId(),requestedRevision)
                .orElseThrow(LockboxSharingService::fileNotFound);

        byte[] packageBytes = decodeExact(
                request.envelope(),
                LockboxShareEnvelopeParser.PACKAGE_LENGTH,
                "envelope"
        );
        LockboxShareEnvelopeParser.ParsedContext context = parser.parse(packageBytes);

        if (!context.ownerPublicUuid().equals(owner.getPublicUuid())
                || !context.clientFileUuid().equals(file.getClientFileId())
                || context.revision() != selectedRevision.getRevision()
                || !MessageDigest.isEqual(context.containerHash(), selectedRevision.getContainerHash())) {
            throw invalid("The share envelope does not match the current Lockbox file.");
        }

        User recipient = users.findByPublicUuid(context.recipientPublicUuid())
                .orElseThrow(LockboxSharingService::recipientUnavailable);
        LockboxKey recipientKey = keys.findByKeyId(context.recipientKeyId())
                .orElseThrow(LockboxSharingService::recipientUnavailable);
        requireKey(
                recipientKey,
                recipient,
                LockboxKey.Role.ENCRYPTION,
                LockboxKey.Algorithm.ML_KEM_1024,
                true
        );

        byte[] signingKeyId = decodeExact(request.ownerSigningKeyId(), 32, "owner signing key ID");
        LockboxKey signingKey = keys.findByKeyId(signingKeyId)
                .orElseThrow(() -> invalid("The owner signing key is unavailable."));
        requireKey(
                signingKey,
                owner,
                LockboxKey.Role.SIGNING,
                LockboxKey.Algorithm.ML_DSA_87,
                false
        );
        if (!MessageDigest.isEqual(signingKeyId, signingKey.getKeyId())) {
            throw invalid("The owner signing key is unavailable.");
        }

        LockboxDevice targetDevice = recipientKey.getDevice();
        if (owner.getId().equals(recipient.getId())
                && Objects.equals(targetDevice.getDeviceUuid(), signingKey.getDevice().getDeviceUuid())) {
            throw LockboxApiException.bad(
                    "LOCKBOX_SELF_SHARE_SAME_DEVICE",
                    "Select another registered device."
            );
        }

        byte[] signature = decodeExact(request.ownerSignature(), 4_627, "owner signature");
        byte[] signatureMessage = signatureMessage(packageBytes);
        try {
            verifier.verify(signingKey.getPublicKey(), signatureMessage, signature);
        } catch (ResponseStatusException exception) {
            throw invalid("The owner signature is invalid.");
        }

        Instant expiresAt = parseExpiry(context.expiresAtUnixSeconds());
        if (shares.existsByShareUuid(context.shareUuid())) {
            throw conflict("LOCKBOX_SHARE_ID_EXISTS", "The share ID already exists.");
        }
        if (shares.existsByRevisionIdAndTargetDeviceId(
                selectedRevision.getId(), targetDevice.getId())) {
            throw conflict(
                    "LOCKBOX_SHARE_ALREADY_EXISTS",
                    "This Lockbox file is already shared with that recipient."
            );
        }

        try {
            LockboxShare share = shares.save(new LockboxShare(
                    context.shareUuid(),
                    selectedRevision,
                    owner,
                    recipient,
                    targetDevice,
                    LockboxShare.Permission.READ,
                    expiresAt
            ));
            envelopes.saveAndFlush(new LockboxShareEnvelope(
                    share,
                    recipientKey,
                    signingKey,
                    packageBytes,
                    signature
            ));
            if (!Objects.equals(share.getTargetDevice().getDeviceUuid(),
                    recipientKey.getDevice().getDeviceUuid())) {
                throw invalid("The share target device is inconsistent.");
            }
            return new LockboxShareResponse(
                    share.getShareUuid().toString(),
                    file.getId(),
                    selectedRevision.getRevision(),
                    owner.getUsername(),
                    recipient.getUsername(),
                    Base64.getEncoder().encodeToString(recipientKey.getKeyId()),
                    share.getStatus().name()
            );
        } catch (DataIntegrityViolationException exception) {
            throw conflict(
                    "LOCKBOX_SHARE_CONFLICT",
                    "The share conflicts with an existing share."
            );
        }
    }

    static byte[] signatureMessage(byte[] packageBytes) {
        byte[] message = new byte[GRANT_DOMAIN.length + packageBytes.length];
        System.arraycopy(GRANT_DOMAIN, 0, message, 0, GRANT_DOMAIN.length);
        System.arraycopy(packageBytes, 0, message, GRANT_DOMAIN.length, packageBytes.length);
        return message;
    }

    private static void requireKey(
            LockboxKey key,
            User expectedOwner,
            LockboxKey.Role expectedRole,
            LockboxKey.Algorithm expectedAlgorithm,
            boolean recipientKey
    ) {
        boolean valid = key.getDevice().getProfile().getUser().getId().equals(expectedOwner.getId())
                && key.getDevice().getStatus() == LockboxDevice.Status.ACTIVE
                && key.getRole() == expectedRole
                && key.getAlgorithm() == expectedAlgorithm
                && key.getStatus() == LockboxKey.Status.ACTIVE;
        if (!valid) {
            if (recipientKey) {
                throw recipientUnavailable();
            }
            throw invalid("The owner signing key is unavailable.");
        }
    }

    private static Instant parseExpiry(long seconds) {
        if (seconds == 0) {
            return null;
        }
        try {
            Instant expiry = Instant.ofEpochSecond(seconds);
            if (!expiry.isAfter(Instant.now())) {
                throw invalid("The share expiry must be in the future.");
            }
            return expiry;
        } catch (DateTimeException exception) {
            throw invalid("The share expiry is invalid.");
        }
    }

    private static byte[] decodeExact(String encoded, int expectedLength, String field) {
        if (encoded == null || encoded.isBlank()) {
            throw invalid(field + " is required.");
        }
        int expectedEncodedLength = 4 * ((expectedLength + 2) / 3);
        if (encoded.length() != expectedEncodedLength) {
            throw invalid(field + " has an invalid length.");
        }
        final byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException exception) {
            throw invalid(field + " is not valid Base64.");
        }
        if (decoded.length != expectedLength) {
            throw invalid(field + " has an invalid length.");
        }
        return decoded;
    }

    private static String normalizeUsername(String username) {
        if (username == null || username.trim().isEmpty() || username.trim().length() > 100) {
            throw recipientUnavailable();
        }
        return username.trim();
    }

    private static LockboxApiException invalid(String message) {
        return LockboxApiException.bad("INVALID_LOCKBOX_SHARE", message);
    }

    private static LockboxApiException recipientUnavailable() {
        return new LockboxApiException(
                "LOCKBOX_RECIPIENT_UNAVAILABLE",
                HttpStatus.NOT_FOUND,
                "The Lockbox recipient is unavailable."
        );
    }

    private static LockboxApiException fileNotFound() {
        return new LockboxApiException(
                "LOCKBOX_FILE_NOT_FOUND",
                HttpStatus.NOT_FOUND,
                "Lockbox file not found."
        );
    }

    private static LockboxApiException conflict(String code, String message) {
        return new LockboxApiException(code, HttpStatus.CONFLICT, message);
    }

    @Transactional(readOnly = true)
    public LockboxReceivedSharesResponse receivedShares(UUID deviceId)
            throws Exception {

        User recipient = access.currentUser();
        LockboxDevice selectedDevice = requireOwnedActiveDevice(deviceId, recipient);
        Instant now = Instant.now();

        List<LockboxShare> availableShares = shares.findReceivedAvailableShares(
                        recipient.getId(),
                        selectedDevice.getDeviceUuid(),
                        LockboxShare.Status.ACTIVE,
                        now,
                        PageRequest.of(0, MAX_RECEIVED_SHARES)
                );

        List<LockboxReceivedShareResponse> responses =
                new ArrayList<>(availableShares.size());

        for (LockboxShare share : availableShares) {
            responses.add(buildReceivedShare(share, selectedDevice));
        }

        return new LockboxReceivedSharesResponse(
                responses
        );
    }

    @Transactional(readOnly = true)
    public LockboxReceivedShareResponse receivedShare(UUID shareUuid, UUID deviceId)
            throws Exception {
        if (shareUuid == null) {
            throw sharedArtifactUnavailable();
        }
        User recipient = access.currentUser();
        LockboxDevice selectedDevice = requireOwnedActiveDevice(deviceId, recipient);
        Instant now = Instant.now();
        LockboxShare share = shares.findReceivedAvailableShare(
                        shareUuid,
                        recipient.getId(),
                        selectedDevice.getDeviceUuid(),
                        LockboxShare.Status.ACTIVE,
                        now
                )
                .orElseThrow(LockboxSharingService::sharedArtifactUnavailable);
        return buildReceivedShare(share, selectedDevice);
    }

    private LockboxReceivedShareResponse buildReceivedShare(
            LockboxShare share, LockboxDevice selectedDevice)
            throws Exception {
        LockboxFileRevision revision = share.getRevision();
        LockboxFile file = revision.getLockboxFile();
        LockboxShareEnvelope envelope = envelopes.findByShareId(share.getId())
                .orElseThrow(LockboxSharingService::sharedArtifactUnavailable);

        Long envelopeRecipientId = envelope.getRecipientKey().getDevice()
                .getProfile().getUser().getId();
        byte[] parsedRecipientKeyId;
        try {
            parsedRecipientKeyId = parser.parse(envelope.getEnvelope()).recipientKeyId();
        } catch (LockboxApiException exception) {
            throw sharedArtifactUnavailable();
        }
        if (!share.getRecipient().getId().equals(envelopeRecipientId)
                || !share.getTargetDevice().getDeviceUuid().equals(selectedDevice.getDeviceUuid())
                || !envelope.getRecipientKey().getDevice().getDeviceUuid().equals(selectedDevice.getDeviceUuid())
                || !MessageDigest.isEqual(parsedRecipientKeyId, envelope.getRecipientKey().getKeyId())) {
            throw sharedArtifactUnavailable();
        }

        byte[] manifest = readBoundedObject(
                revision.getManifestObjectKey(), MAX_MANIFEST_SIZE, "manifest");
        byte[] fileSignature = readBoundedObject(
                revision.getSignatureObjectKey(), MAX_SIGNATURE_SIZE, "signature");
        byte[] encryptedHeader = readContainerHeader(revision.getContainerObjectKey());
        LockboxKey ownerSigningKey = envelope.getOwnerSigningKey();
        Base64.Encoder base64 = Base64.getEncoder();

        return new LockboxReceivedShareResponse(
                share.getShareUuid().toString(),
                file.getId(),
                file.getClientFileId().toString(),
                revision.getRevision(),
                share.getOwner().getUsername(),
                share.getPermission().name(),
                share.getCreatedAt(),
                share.getExpiresAt(),
                base64.encodeToString(envelope.getEnvelope()),
                base64.encodeToString(ownerSigningKey.getKeyId()),
                base64.encodeToString(ownerSigningKey.getPublicKey()),
                base64.encodeToString(envelope.getOwnerSignature()),
                base64.encodeToString(manifest),
                base64.encodeToString(fileSignature),
                base64.encodeToString(encryptedHeader)
        );
    }

    private byte[] readBoundedObject(
            String objectKey,
            int maximumSize,
            String artifactName
    ) throws Exception {

        try {
            long size = objectStorage.size(objectKey);
            if (size < 1 || size > maximumSize) {
                throw sharedArtifactUnavailable();
            }

            try (InputStream input = objectStorage.download(objectKey)) {

                byte[] bytes = input.readNBytes(maximumSize + 1);

                if (bytes.length != size
                        || bytes.length > maximumSize
                        || input.read() != -1) {
                    throw sharedArtifactUnavailable();
                }

                return bytes;
            }
        } catch (LockboxApiException exception) {
            throw exception;
        } catch (Exception exception) {
            throw sharedArtifactUnavailable();
        }
    }

    private byte[] readContainerHeader(
            String objectKey
    ) throws Exception {

        try {
            long objectSize = objectStorage.size(objectKey);
            if (objectSize < 32) {
                throw sharedArtifactUnavailable();
            }

            try (InputStream input = objectStorage.download(objectKey)) {

            byte[] preamble = input.readNBytes(32);

            if (preamble.length != 32) {
                throw sharedArtifactUnavailable();
            }

            long headerLength = Integer.toUnsignedLong(
                    ByteBuffer
                            .wrap(preamble, 12, 4)
                            .order(ByteOrder.LITTLE_ENDIAN)
                            .getInt()
            );

            if (headerLength < 32
                    || headerLength > MAX_HEADER_SIZE
                    || headerLength > objectSize) {
                throw sharedArtifactUnavailable();
            }

            byte[] header = new byte[(int) headerLength];

            System.arraycopy(
                    preamble,
                    0,
                    header,
                    0,
                    preamble.length
            );

            int remainingLength =
                    header.length - preamble.length;

            byte[] remaining =
                    input.readNBytes(remainingLength);

            if (remaining.length != remainingLength) {
                throw sharedArtifactUnavailable();
            }

            System.arraycopy(
                    remaining,
                    0,
                    header,
                    preamble.length,
                    remaining.length
            );

                return header;
            }
        } catch (LockboxApiException exception) {
            throw exception;
        } catch (Exception exception) {
            throw sharedArtifactUnavailable();
        }
    }

    private static LockboxApiException
    sharedArtifactUnavailable() {

        return new LockboxApiException(
                "LOCKBOX_SHARE_UNAVAILABLE",
                HttpStatus.NOT_FOUND,
                "The shared Lockbox file is unavailable."
        );
    }

    @Transactional(readOnly = true)
    public LockboxDownloadResult openReceivedContainer(
            UUID shareUuid,
            UUID deviceId
    ) throws Exception {

        if (shareUuid == null) {
            throw sharedArtifactUnavailable();
        }

        User recipient = access.currentUser();
        LockboxDevice selectedDevice = requireOwnedActiveDevice(deviceId, recipient);

        LockboxShare share = shares.findReceivedAvailableShare(
                        shareUuid,
                        recipient.getId(),
                        selectedDevice.getDeviceUuid(),
                        LockboxShare.Status.ACTIVE,
                        Instant.now()
                )
                .orElseThrow(
                        LockboxSharingService::sharedArtifactUnavailable
                );

        LockboxShareEnvelope envelope = envelopes.findByShareId(share.getId())
                .orElseThrow(LockboxSharingService::sharedArtifactUnavailable);
        if (!share.getTargetDevice().getDeviceUuid().equals(selectedDevice.getDeviceUuid())
                || !envelope.getRecipientKey().getDevice().getDeviceUuid()
                .equals(selectedDevice.getDeviceUuid())) {
            throw sharedArtifactUnavailable();
        }

        if (share.getPermission() != LockboxShare.Permission.READ) {
            throw sharedArtifactUnavailable();
        }

        LockboxFileRevision revision = share.getRevision();
        LockboxFile file = revision.getLockboxFile();

        long actualSize;

        try {
            actualSize = objectStorage.size(
                    revision.getContainerObjectKey()
            );
        } catch (Exception exception) {
            throw sharedArtifactUnavailable();
        }

        if (actualSize < 1
                || actualSize != revision.getContainerSize()) {
            throw sharedArtifactUnavailable();
        }

        InputStream inputStream;

        try {
            inputStream = objectStorage.download(
                    revision.getContainerObjectKey()
            );
        } catch (Exception exception) {
            throw sharedArtifactUnavailable();
        }

        return new LockboxDownloadResult(
                file.getClientFileId() + ".fdcse",
                actualSize,
                LockboxObjectStorage.ArtifactType.CONTAINER.contentType(),
                inputStream
        );
    }

    private LockboxDevice requireOwnedActiveDevice(UUID deviceId, User user) {
        if (deviceId == null) {
            throw sharedArtifactUnavailable();
        }
        return devices.findOwnedActiveDevice(
                        deviceId, user.getId(), LockboxDevice.Status.ACTIVE)
                .orElseThrow(LockboxSharingService::sharedArtifactUnavailable);
    }
}
