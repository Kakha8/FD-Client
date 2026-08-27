package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.dto.lockbox.*;
import kakha.kudava.filedrivespring.enums.DriveSpace;
import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import kakha.kudava.filedrivespring.model.FileMetaData;
import kakha.kudava.filedrivespring.model.Folders;
import kakha.kudava.filedrivespring.model.LockboxDevice;
import kakha.kudava.filedrivespring.model.LockboxFile;
import kakha.kudava.filedrivespring.model.LockboxFileRevision;
import kakha.kudava.filedrivespring.model.LockboxKey;
import kakha.kudava.filedrivespring.model.LockboxProfile;
import kakha.kudava.filedrivespring.model.User;
import kakha.kudava.filedrivespring.records.LockboxDownloadResult;
import kakha.kudava.filedrivespring.repository.FileMetaDataRepository;
import kakha.kudava.filedrivespring.repository.FolderRepository;
import kakha.kudava.filedrivespring.repository.LockboxFileRepository;
import kakha.kudava.filedrivespring.repository.LockboxFileRevisionRepository;
import kakha.kudava.filedrivespring.repository.LockboxKeyRepository;
import kakha.kudava.filedrivespring.repository.LockboxProfileRepository;
import kakha.kudava.filedrivespring.services.ResourceAccessService;
import kakha.kudava.filedrivespring.services.objects.RootFolderService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;

@Service
public class LockboxService {
    private static final Logger log = LoggerFactory.getLogger(LockboxService.class);

    private static final byte[] SIGNING_DOMAIN =
            "FD-LOCKBOX-MANIFEST-V1\0"
                    .getBytes(StandardCharsets.US_ASCII);

    private static final int CSEMLK03_PREAMBLE_SIZE = 32;
    private static final int MAX_HEADER_SIZE = 1024 * 1024;
    private static final int MAX_MANIFEST_SIZE = 1024;
    private static final int MAX_SIGNATURE_SIZE = 16 * 1024;

    private final LockboxManifestParser manifests;
    private final LockboxSignatureRecordParser signatures;
    private final LockboxV3ContainerValidator containers;
    private final LockboxSignatureVerifier verifier;
    private final LockboxObjectStorage storage;
    private final FileMetaDataRepository files;
    private final FolderRepository folders;
    private final LockboxFileRepository lockboxFiles;
    private final LockboxFileRevisionRepository revisions;
    private final LockboxKeyRepository keys;
    private final LockboxProfileRepository profiles;
    private final RootFolderService roots;
    private final ResourceAccessService access;

    private final long maxContainer;
    private final long maxManifest;
    private final long maxSignature;

    public LockboxService(
            LockboxManifestParser manifests,
            LockboxSignatureRecordParser signatures,
            LockboxV3ContainerValidator containers,
            LockboxSignatureVerifier verifier,
            LockboxObjectStorage storage,
            FileMetaDataRepository files,
            FolderRepository folders,
            LockboxFileRepository lockboxFiles,
            LockboxFileRevisionRepository revisions,
            LockboxKeyRepository keys,
            LockboxProfileRepository profiles,
            RootFolderService roots,
            ResourceAccessService access,
            @Value("${lockbox.upload.max-container-size}")
            long maxContainer,
            @Value("${lockbox.upload.max-manifest-size}")
            long maxManifest,
            @Value("${lockbox.upload.max-signature-size}")
            long maxSignature
    ) {
        this.manifests = manifests;
        this.signatures = signatures;
        this.containers = containers;
        this.verifier = verifier;
        this.storage = storage;
        this.files = files;
        this.folders = folders;
        this.lockboxFiles = lockboxFiles;
        this.revisions = revisions;
        this.keys = keys;
        this.profiles = profiles;
        this.roots = roots;
        this.access = access;
        this.maxContainer = maxContainer;
        this.maxManifest = maxManifest;
        this.maxSignature = maxSignature;
    }

    @Transactional(rollbackFor = Exception.class)
    public LockboxUploadResponse upload(
            MultipartFile container,
            MultipartFile manifest,
            MultipartFile signature,
            Long parentId
    ) throws Exception {
        User user = access.currentUser();

        LockboxProfile profile = profiles
                .findByUserId(user.getId())
                .filter(existing ->
                        existing.getStatus()
                                == LockboxProfile.Status.ENABLED
                )
                .orElseThrow(() ->
                        new LockboxApiException(
                                "LOCKBOX_NOT_ENABLED",
                                HttpStatus.FORBIDDEN,
                                "Lockbox is not enabled."
                        )
                );

        Folders parent = resolveParent(
                parentId,
                user
        );

        Path temporaryDirectory =
                Files.createTempDirectory("lockbox-v3-");

        Path containerPath =
                temporaryDirectory.resolve("container");

        Path manifestPath =
                temporaryDirectory.resolve("manifest");

        Path signaturePath =
                temporaryDirectory.resolve("signature");

        List<String> uploadedObjects =
                new ArrayList<>();

        try {
            stage(
                    container,
                    containerPath,
                    maxContainer
            );

            stage(
                    manifest,
                    manifestPath,
                    maxManifest
            );

            stage(
                    signature,
                    signaturePath,
                    maxSignature
            );

            byte[] manifestBytes = readExact(
                    manifestPath,
                    maxManifest
            );

            byte[] signatureBytes = readExact(
                    signaturePath,
                    maxSignature
            );

            LockboxSignatureRecordParser.SignatureRecord
                    signatureRecord =
                    signatures.parse(signatureBytes);

            LockboxKey signingKey = findKey(
                    profile,
                    LockboxKey.Role.SIGNING,
                    signatureRecord.signingKeyId(),
                    "UNKNOWN_SIGNING_KEY"
            );

            LockboxDevice device =
                    signingKey.getDevice();

            if (device.getStatus()
                    != LockboxDevice.Status.ACTIVE) {

                throw LockboxApiException.bad(
                        "DEVICE_NOT_ACTIVE",
                        "Signing device is not active."
                );
            }

            byte[] transcript =
                    signingTranscript(manifestBytes);

            try {
                verifier.verify(
                        signingKey.getPublicKey(),
                        transcript,
                        signatureRecord.signature()
                );
            } catch (RuntimeException exception) {
                throw LockboxApiException.bad(
                        "INVALID_SIGNATURE",
                        "Manifest signature is invalid."
                );
            }

            LockboxManifestParser.Manifest parsedManifest =
                    manifests.parse(manifestBytes);

            if (!MessageDigest.isEqual(
                    signatureRecord.signingKeyId(),
                    parsedManifest.signingKeyId()
            )) {
                throw LockboxApiException.bad(
                        "INVALID_SIGNATURE",
                        "Signing key IDs do not match."
                );
            }

            if (!device.getDeviceUuid().equals(
                    parsedManifest.deviceUuid()
            )) {
                throw LockboxApiException.bad(
                        "DEVICE_NOT_ACTIVE",
                        "Manifest device is invalid."
                );
            }

            if (parsedManifest.revision() != 1
                    || !allZero(
                    parsedManifest.previousManifestHash()
            )) {
                throw LockboxApiException.bad(
                        "UNSUPPORTED_REVISION",
                        "Only initial revision 1 is supported."
                );
            }

            validateNames(
                    container,
                    manifest,
                    signature,
                    parsedManifest.clientFileId()
            );

            long actualContainerSize =
                    Files.size(containerPath);

            if (actualContainerSize
                    != parsedManifest.containerSize()) {

                throw LockboxApiException.bad(
                        "CONTAINER_SIZE_MISMATCH",
                        "Container size does not match "
                                + "the signed manifest."
                );
            }

            byte[] actualContainerHash =
                    calculateSha3_512(containerPath);

            if (!MessageDigest.isEqual(
                    actualContainerHash,
                    parsedManifest.containerHash()
            )) {
                throw LockboxApiException.bad(
                        "CONTAINER_HASH_MISMATCH",
                        "Container hash does not match "
                                + "the signed manifest."
                );
            }

            LockboxV3ContainerValidator.Container
                    parsedContainer =
                    containers.validate(
                            containerPath,
                            actualContainerSize
                    );

            boolean matchingContainer =
                    parsedContainer.clientFileId().equals(
                            parsedManifest.clientFileId()
                    )
                            && parsedContainer.suiteId()
                            == parsedManifest.suiteId()
                            && MessageDigest.isEqual(
                            parsedContainer.encryptionKeyId(),
                            parsedManifest.encryptionKeyId()
                    );

            if (!matchingContainer) {
                throw LockboxApiException.bad(
                        "MANIFEST_CONTAINER_MISMATCH",
                        "Container public fields do not match "
                                + "the signed manifest."
                );
            }

            findKey(
                    profile,
                    LockboxKey.Role.ENCRYPTION,
                    parsedManifest.encryptionKeyId(),
                    "UNKNOWN_ENCRYPTION_KEY"
            );

            /*
             * Check whether this exact signed file identity already exists.
             */
            if (lockboxFiles.existsByProfileIdAndClientFileId(
                    profile.getId(), parsedManifest.clientFileId())) {
                throwDuplicate();
            }

            /*
             * No previous entry exists: perform a normal new upload.
             */
            String objectPrefix =
                    "users/"
                            + user.getId()
                            + "/lockbox/"
                            + parsedManifest.clientFileId()
                            + "/1/requests/"
                            + UUID.randomUUID()
                            + "/";

            String containerObjectKey =
                    objectPrefix + "container.fdcse";

            String manifestObjectKey =
                    objectPrefix + "manifest.fdmanifest";

            String signatureObjectKey =
                    objectPrefix + "signature.fdsig";

            registerRollbackCleanup(
                    uploadedObjects
            );

            uploadObject(
                    containerObjectKey,
                    containerPath,
                    LockboxObjectStorage.ArtifactType.CONTAINER,
                    uploadedObjects
            );

            uploadObject(
                    manifestObjectKey,
                    manifestPath,
                    LockboxObjectStorage.ArtifactType.MANIFEST,
                    uploadedObjects
            );

            uploadObject(
                    signatureObjectKey,
                    signaturePath,
                    LockboxObjectStorage.ArtifactType.SIGNATURE,
                    uploadedObjects
            );

            FileMetaData metadata =
                    new FileMetaData();

            metadata.setObjectKey(
                    containerObjectKey
            );

            metadata.setFileName(
                    parsedManifest.clientFileId()
                            + ".fdcse"
            );

            metadata.setObjectType(
                    LockboxObjectStorage.ArtifactType
                            .CONTAINER
                            .contentType()
            );

            metadata.setChecksum(
                    HexFormat.of().formatHex(
                            actualContainerHash
                    )
            );

            metadata.setCreationDate(
                    Instant.now()
            );

            metadata.setSize(
                    actualContainerSize
            );

            metadata.setOwner(user);
            metadata.setParent(parent);
            metadata.setDriveSpace(
                    DriveSpace.LOCKBOX
            );

            FileMetaData savedMetadata =
                    files.saveAndFlush(metadata);

            LockboxFile lockboxFile = new LockboxFile(
                    savedMetadata, profile, parsedManifest.clientFileId(), 1);

            try {
                lockboxFiles.saveAndFlush(
                        lockboxFile
                );
                revisions.saveAndFlush(new LockboxFileRevision(lockboxFile, 1, 3, 1,
                        actualContainerSize, actualContainerHash, parsedManifest.encryptionKeyId(),
                        parsedManifest.signingKeyId(), parsedManifest.deviceUuid(),
                        parsedContainer.chunkSize(), parsedContainer.chunkCount(), containerObjectKey,
                        manifestObjectKey, signatureObjectKey));
            } catch (DataIntegrityViolationException exception) {
                throwDuplicate();
            }

            return new LockboxUploadResponse(
                    savedMetadata.getId(),
                    parsedManifest.clientFileId(),
                    parsedManifest.revision(),
                    parent.getId(),
                    actualContainerSize,
                    HexFormat.of().formatHex(
                            actualContainerHash
                    ),
                    3,
                    1,
                    lockboxFile.getCreatedAt()
            );
        } catch (Exception exception) {
            if (!TransactionSynchronizationManager
                    .isSynchronizationActive()) {

                cleanupUploadedObjects(
                        uploadedObjects,
                        exception
                );
            }

            throw exception;
        } finally {
            deleteTree(temporaryDirectory);
        }
    }

    @Transactional(rollbackFor = Exception.class)
    public LockboxUploadResponse uploadRevision(Long fileId,long expectedRevision,MultipartFile container,
            MultipartFile manifest,MultipartFile signature) throws Exception {
        User user=access.currentUser();
        LockboxFile logical=lockboxFiles.findForUpdateByIdAndProfileUserId(fileId,user.getId())
                .orElseThrow(LockboxService::notFound);
        if(logical.getFile().isDeleted()||logical.getFile().isPermanentlyDeleted())throw notFound();
        LockboxProfile profile=logical.getProfile();
        if(profile.getStatus()!=LockboxProfile.Status.ENABLED){
            throw new LockboxApiException("LOCKBOX_NOT_ENABLED",HttpStatus.FORBIDDEN,"Lockbox is not enabled.");
        }
        if(logical.getCurrentRevision()!=expectedRevision)throw revisionConflict();
        LockboxFileRevision previous=revisions.findByLockboxFileIdAndRevision(logical.getId(),expectedRevision)
                .orElseThrow(()->new IllegalStateException("Previous Lockbox revision is missing."));
        Path temporaryDirectory=Files.createTempDirectory("lockbox-revision-");
        Path containerPath=temporaryDirectory.resolve("container"),manifestPath=temporaryDirectory.resolve("manifest"),signaturePath=temporaryDirectory.resolve("signature");
        List<String> uploadedObjects=new ArrayList<>();
        try{
            stage(container,containerPath,maxContainer);stage(manifest,manifestPath,maxManifest);stage(signature,signaturePath,maxSignature);
            byte[] manifestBytes=readExact(manifestPath,maxManifest),signatureBytes=readExact(signaturePath,maxSignature);
            var parsedManifest=manifests.parse(manifestBytes);var signatureRecord=signatures.parse(signatureBytes);
            if(!parsedManifest.clientFileId().equals(logical.getClientFileId())||parsedManifest.revision()!=expectedRevision+1)
                throw LockboxApiException.bad("UNSUPPORTED_REVISION","Revision identity or sequence is invalid.");
            byte[] previousManifest=readBoundedObject(previous.getManifestObjectKey(),MAX_MANIFEST_SIZE,"manifest");
            MessageDigest digest=MessageDigest.getInstance("SHA3-512");
            if(!MessageDigest.isEqual(digest.digest(previousManifest),parsedManifest.previousManifestHash()))
                throw LockboxApiException.bad("INVALID_REVISION_CHAIN","Previous manifest hash is invalid.");
            LockboxKey signingKey=findKey(profile,LockboxKey.Role.SIGNING,signatureRecord.signingKeyId(),"UNKNOWN_SIGNING_KEY");
            if(signingKey.getDevice().getStatus()!=LockboxDevice.Status.ACTIVE||!signingKey.getDevice().getDeviceUuid().equals(parsedManifest.deviceUuid()))
                throw LockboxApiException.bad("DEVICE_NOT_ACTIVE","Manifest device is invalid.");
            if(!MessageDigest.isEqual(signatureRecord.signingKeyId(),parsedManifest.signingKeyId()))
                throw LockboxApiException.bad("INVALID_SIGNATURE","Signing key IDs do not match.");
            try{verifier.verify(signingKey.getPublicKey(),signingTranscript(manifestBytes),signatureRecord.signature());}
            catch(RuntimeException exception){throw LockboxApiException.bad("INVALID_SIGNATURE","Manifest signature is invalid.");}
            validateNames(container,manifest,signature,logical.getClientFileId());
            long actualSize=Files.size(containerPath);
            if(actualSize!=parsedManifest.containerSize())throw LockboxApiException.bad("CONTAINER_SIZE_MISMATCH","Container size does not match the signed manifest.");
            byte[] actualHash=calculateSha3_512(containerPath);
            if(!MessageDigest.isEqual(actualHash,parsedManifest.containerHash()))throw LockboxApiException.bad("CONTAINER_HASH_MISMATCH","Container hash does not match the signed manifest.");
            var parsedContainer=containers.validate(containerPath,actualSize);
            if(!parsedContainer.clientFileId().equals(logical.getClientFileId())||parsedContainer.suiteId()!=parsedManifest.suiteId()||!MessageDigest.isEqual(parsedContainer.encryptionKeyId(),parsedManifest.encryptionKeyId()))
                throw LockboxApiException.bad("MANIFEST_CONTAINER_MISMATCH","Container public fields do not match the signed manifest.");
            findKey(profile,LockboxKey.Role.ENCRYPTION,parsedManifest.encryptionKeyId(),"UNKNOWN_ENCRYPTION_KEY");
            if(revisions.existsByLockboxFileIdAndRevision(logical.getId(),parsedManifest.revision()))throw revisionConflict();
            String prefix="users/"+user.getId()+"/lockbox/"+logical.getClientFileId()+"/"+parsedManifest.revision()+"/requests/"+UUID.randomUUID()+"/";
            String containerKey=prefix+"container.fdcse",manifestKey=prefix+"manifest.fdmanifest",signatureKey=prefix+"signature.fdsig";
            registerRollbackCleanup(uploadedObjects);
            uploadObject(containerKey,containerPath,LockboxObjectStorage.ArtifactType.CONTAINER,uploadedObjects);
            uploadObject(manifestKey,manifestPath,LockboxObjectStorage.ArtifactType.MANIFEST,uploadedObjects);
            uploadObject(signatureKey,signaturePath,LockboxObjectStorage.ArtifactType.SIGNATURE,uploadedObjects);
            try{
                LockboxFileRevision saved=revisions.saveAndFlush(new LockboxFileRevision(logical,parsedManifest.revision(),3,1,actualSize,actualHash,parsedManifest.encryptionKeyId(),parsedManifest.signingKeyId(),parsedManifest.deviceUuid(),parsedContainer.chunkSize(),parsedContainer.chunkCount(),containerKey,manifestKey,signatureKey));
                logical.advanceToRevision(expectedRevision,parsedManifest.revision());lockboxFiles.saveAndFlush(logical);
                FileMetaData metadata=logical.getFile();metadata.setObjectKey(containerKey);metadata.setSize(actualSize);metadata.setChecksum(HexFormat.of().formatHex(actualHash));metadata.setLastModifiedDate(Instant.now());files.save(metadata);
                return new LockboxUploadResponse(logical.getId(),logical.getClientFileId(),saved.getRevision(),metadata.getParent()==null?null:metadata.getParent().getId(),actualSize,HexFormat.of().formatHex(actualHash),3,1,saved.getCreatedAt());
            }catch(DataIntegrityViolationException|IllegalStateException exception){throw revisionConflict();}
        }catch(Exception exception){if(!TransactionSynchronizationManager.isSynchronizationActive())cleanupUploadedObjects(uploadedObjects,exception);throw exception;}
        finally{deleteTree(temporaryDirectory);}
    }

    @Transactional(readOnly=true)
    public LockboxRevisionHistoryResponse revisionHistory(Long fileId){
        User user=access.currentUser();LockboxFile file=requireOwnedLockboxFile(fileId,user);
        if(file.getFile().isDeleted()||file.getFile().isPermanentlyDeleted())throw notFound();
        return new LockboxRevisionHistoryResponse(file.getId(),file.getClientFileId(),file.getCurrentRevision(),
                revisions.findAllByLockboxFileIdOrderByRevisionDesc(file.getId()).stream().map(r->new LockboxRevisionItemResponse(r.getRevision(),r.getContainerSize(),HexFormat.of().formatHex(r.getContainerHash()),r.getCreatedAt(),r.getRevision()==file.getCurrentRevision())).toList());
    }

    @Transactional(readOnly=true)
    public LockboxDownloadResult openRevisionDownload(Long fileId,long revision,LockboxObjectStorage.ArtifactType type)throws Exception{
        LockboxFile file=requireOwnedLockboxFile(fileId,access.currentUser());
        if(file.getFile().isDeleted()||file.getFile().isPermanentlyDeleted())throw notFound();
        LockboxFileRevision selected=revisions.findByLockboxFileIdAndRevision(file.getId(),revision).orElseThrow(LockboxService::notFound);
        String key=switch(type){case CONTAINER->selected.getContainerObjectKey();case MANIFEST->selected.getManifestObjectKey();case SIGNATURE->selected.getSignatureObjectKey();};
        long size=storage.size(key);if(type==LockboxObjectStorage.ArtifactType.CONTAINER&&size!=selected.getContainerSize())throw new IllegalStateException("Stored Lockbox container size does not match its database record.");
        String extension=switch(type){case CONTAINER->".fdcse";case MANIFEST->".fdmanifest";case SIGNATURE->".fdsig";};
        return new LockboxDownloadResult(file.getClientFileId()+"-r"+revision+extension,size,type.contentType(),storage.download(key));
    }

    private static LockboxApiException notFound(){return new LockboxApiException("LOCKBOX_FILE_NOT_FOUND",HttpStatus.NOT_FOUND,"Lockbox file not found.");}
    private static LockboxApiException revisionConflict(){return new LockboxApiException("LOCKBOX_REVISION_CONFLICT",HttpStatus.CONFLICT,"The Lockbox file revision changed. Refresh and retry.");}

    @Transactional(readOnly = true)
    public LockboxDownloadResult openDownload(
            Long fileId,
            LockboxObjectStorage.ArtifactType artifactType
    ) throws Exception {

        if (fileId == null || artifactType == null) {
            throw new LockboxApiException(
                    "LOCKBOX_FILE_NOT_FOUND",
                    HttpStatus.NOT_FOUND,
                    "Lockbox file not found."
            );
        }

        User user = access.currentUser();

        LockboxFile file = lockboxFiles
                .findByIdAndProfileUserId(
                        fileId,
                        user.getId()
                )
                .orElseThrow(() ->
                        new LockboxApiException(
                                "LOCKBOX_FILE_NOT_FOUND",
                                HttpStatus.NOT_FOUND,
                                "Lockbox file not found."
                        )
                );
        if(file.getFile().isDeleted()||file.getFile().isPermanentlyDeleted())throw notFound();
        LockboxFileRevision revision = currentRevision(file);

        String baseName =
                file.getClientFileId().toString();

        String objectKey;
        String fileName;

        switch (artifactType) {
            case CONTAINER -> {
                objectKey =
                        revision.getContainerObjectKey();

                fileName =
                        baseName + ".fdcse";
            }

            case MANIFEST -> {
                objectKey =
                        revision.getManifestObjectKey();

                fileName =
                        baseName + ".fdmanifest";
            }

            case SIGNATURE -> {
                objectKey =
                        revision.getSignatureObjectKey();

                fileName =
                        baseName + ".fdsig";
            }

            default -> throw new IllegalStateException(
                    "Unsupported Lockbox artifact type."
            );
        }

        long actualSize =
                storage.size(objectKey);

        if (artifactType
                == LockboxObjectStorage.ArtifactType.CONTAINER
                && actualSize != revision.getContainerSize()) {
            throw new IllegalStateException(
                    "Stored Lockbox container size "
                            + "does not match its database record."
            );
        }

        InputStream input =
                storage.download(objectKey);

        return new LockboxDownloadResult(
                fileName,
                actualSize,
                artifactType.contentType(),
                input
        );
    }

    @Transactional(readOnly = true)
    public LockboxPrivateMetadataResponse privateMetadata(
            Long fileId
    ) throws Exception {

        if (fileId == null) {
            throw new LockboxApiException(
                    "LOCKBOX_FILE_NOT_FOUND",
                    HttpStatus.NOT_FOUND,
                    "Lockbox file not found."
            );
        }

        User user = access.currentUser();

        LockboxFile file = lockboxFiles
                .findByIdAndProfileUserId(
                        fileId,
                        user.getId()
                )
                .orElseThrow(() ->
                        new LockboxApiException(
                                "LOCKBOX_FILE_NOT_FOUND",
                                HttpStatus.NOT_FOUND,
                                "Lockbox file not found."
                        )
                );
        LockboxFileRevision revision = currentRevision(file);

        byte[] manifest = readBoundedObject(
                revision.getManifestObjectKey(),
                MAX_MANIFEST_SIZE,
                "manifest"
        );

        byte[] signature = readBoundedObject(
                revision.getSignatureObjectKey(),
                MAX_SIGNATURE_SIZE,
                "signature"
        );

        byte[] encryptedHeader =
                readContainerHeader(
                        revision.getContainerObjectKey()
                );

        return new LockboxPrivateMetadataResponse(
                file.getId(),
                file.getClientFileId(),
                revision.getRevision(),
                Base64.getEncoder()
                        .encodeToString(manifest),
                Base64.getEncoder()
                        .encodeToString(signature),
                Base64.getEncoder()
                        .encodeToString(encryptedHeader)
        );
    }

    @Transactional(readOnly = true)
    public LockboxFolderViewResponse viewRoot() {
        User user = access.currentUser();

        Folders root =
                roots.ensureLockboxRootFolder(user);

        return view(root, user);
    }

    @Transactional(readOnly = true)
    public LockboxFolderViewResponse viewFolder(
            Long folderId
    ) {
        User user = access.currentUser();

        Folders folder =
                ownedFolder(folderId, user);

        return view(folder, user);
    }

    @Transactional
    public void deleteLockboxFile(
            Long fileId
    ) throws Exception {

        User user = access.currentUser();

        LockboxFile lockboxFile =
                requireOwnedLockboxFile(
                        fileId,
                        user
                );

        FileMetaData metadata =
                lockboxFile.getFile();

        if (metadata.isPermanentlyDeleted()) {
            return; // idempotent
        }

        List<String> objectKeys = revisions.findAllByLockboxFileIdOrderByRevisionDesc(lockboxFile.getId())
                .stream().flatMap(revision -> java.util.stream.Stream.of(
                        revision.getContainerObjectKey(), revision.getManifestObjectKey(),
                        revision.getSignatureObjectKey())).toList();

        Instant deletedAt = Instant.now();

        // Keep the DB row as a tombstone/deletion record.
        metadata.setDeleted(true);
        metadata.setDeletedAt(deletedAt);
        metadata.setPermanentlyDeleted(true);
        metadata.setPermanentlyDeletedAt(deletedAt);

        files.saveAndFlush(metadata);
        List<String> committedKeys=List.copyOf(objectKeys);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization(){
            @Override public void afterCommit(){deleteCommittedObjects(committedKeys);}
        });
    }

    private void deleteCommittedObjects(List<String> objectKeys){
        for(String objectKey:objectKeys){
            try{storage.delete(objectKey);}
            catch(Exception exception){log.error("Failed to delete committed Lockbox object key {}; manual cleanup retry is required.",objectKey,exception);}
        }
    }

    private LockboxFile requireOwnedLockboxFile(
            Long fileId,
            User user
    ) {
        return lockboxFiles
                .findByIdAndProfileUserId(
                        fileId,
                        user.getId()
                )
                .orElseThrow(
                        () -> new LockboxApiException(
                                "LOCKBOX_FILE_NOT_FOUND",
                                HttpStatus.NOT_FOUND,
                                "Lockbox file not found."
                        )
                );
    }

    private LockboxFolderViewResponse view(
            Folders parent,
            User user
    ) {
        List<LockboxFolderItemResponse>
                folderResponses =
                folders.findFoldersByParent_Id(
                                parent.getId()
                        )
                        .stream()
                        .filter(folder ->
                                folder.getDriveSpace()
                                        == DriveSpace.LOCKBOX
                        )
                        .filter(folder ->
                                !folder.isDeleted()
                        )
                        .filter(folder ->
                                !folder.isPermanentlyDeleted()
                        )
                        .filter(folder ->
                                owned(folder, user)
                        )
                        .map(folder ->
                                new LockboxFolderItemResponse(
                                        folder.getId(),
                                        folder.getName(),
                                        parent.getId()
                                )
                        )
                        .toList();

        List<FileMetaData> metadataFiles =
                files.findByParent_IdAndDeletedFalse(
                                parent.getId()
                        )
                        .stream()
                        .filter(file ->
                                file.getDriveSpace()
                                        == DriveSpace.LOCKBOX
                        )
                        .filter(file ->
                                !file.isPermanentlyDeleted()
                        )
                        .filter(file ->
                                file.getOwner() != null
                                        && Objects.equals(
                                        file.getOwner().getId(),
                                        user.getId()
                                )
                        )
                        .toList();

        Map<Long, LockboxFile> lockboxById =
                new HashMap<>();

        List<Long> metadataIds =
                metadataFiles.stream()
                        .map(FileMetaData::getId)
                        .toList();

        lockboxFiles.findAllById(metadataIds)
                .forEach(file ->
                        lockboxById.put(
                                file.getId(),
                                file
                        )
                );

        List<LockboxFileItemResponse>
                fileResponses =
                metadataFiles.stream()
                        .map(metadata -> {
                            LockboxFile lockboxFile =
                                    lockboxById.get(
                                            metadata.getId()
                                    );

                            if (lockboxFile == null) {
                                throw new IllegalStateException(
                                        "Lockbox metadata is missing."
                                );
                            }

                            return new LockboxFileItemResponse(
                                    lockboxFile.getId(),
                                    lockboxFile.getClientFileId(),
                                    lockboxFile.getCurrentRevision(),
                                    currentRevision(lockboxFile).getContainerSize(),
                                    lockboxFile.getCreatedAt(),
                                    currentRevision(lockboxFile).getFormatVersion(),
                                    currentRevision(lockboxFile).getSuiteId()
                            );
                        })
                        .toList();

        return new LockboxFolderViewResponse(
                parent.getId(),
                parent.getName(),
                parent.getParent() == null
                        ? null
                        : parent.getParent().getId(),
                folderResponses,
                fileResponses
        );
    }

    private LockboxKey findKey(
            LockboxProfile profile,
            LockboxKey.Role role,
            byte[] keyId,
            String errorCode
    ) {
        return keys
                .findAllByDeviceProfileIdAndRoleAndStatus(
                        profile.getId(),
                        role,
                        LockboxKey.Status.ACTIVE
                )
                .stream()
                .filter(key ->
                        MessageDigest.isEqual(
                                key.getKeyId(),
                                keyId
                        )
                )
                .findFirst()
                .orElseThrow(() ->
                        LockboxApiException.bad(
                                errorCode,
                                "Registered active key was not found."
                        )
                );
    }

    private Folders resolveParent(
            Long folderId,
            User user
    ) {
        if (folderId == null) {
            return roots.ensureLockboxRootFolder(
                    user
            );
        }

        return ownedFolder(folderId, user);
    }

    private Folders ownedFolder(
            Long folderId,
            User user
    ) {
        if (folderId == null) {
            throw LockboxApiException.bad(
                    "INVALID_LOCKBOX_FOLDER",
                    "Destination Lockbox folder is invalid."
            );
        }

        Folders folder =
                access.requireFolderOwner(folderId);

        boolean invalid =
                folder.getDriveSpace()
                        != DriveSpace.LOCKBOX
                        || folder.isDeleted()
                        || folder.isPermanentlyDeleted()
                        || !owned(folder, user);

        if (invalid) {
            throw LockboxApiException.bad(
                    "INVALID_LOCKBOX_FOLDER",
                    "Destination Lockbox folder is invalid."
            );
        }

        return folder;
    }

    private boolean owned(
            Folders folder,
            User user
    ) {
        return folder.getOwner() != null
                && Objects.equals(
                folder.getOwner().getId(),
                user.getId()
        );
    }

    private static void stage(
            MultipartFile part,
            Path destination,
            long maximumSize
    ) throws IOException {

        if (part == null || part.isEmpty()) {
            throw LockboxApiException.bad(
                    "INVALID_MANIFEST",
                    "All three artifacts are required."
            );
        }

        try (
                InputStream input =
                        part.getInputStream();

                OutputStream output =
                        Files.newOutputStream(destination)
        ) {
            byte[] buffer =
                    new byte[64 * 1024];

            long total = 0;

            for (
                    int count;
                    (count = input.read(buffer)) != -1;
            ) {
                try {
                    total = Math.addExact(
                            total,
                            count
                    );
                } catch (ArithmeticException exception) {
                    throw LockboxApiException.bad(
                            "ARTIFACT_TOO_LARGE",
                            "Lockbox artifact size overflowed."
                    );
                }

                if (total > maximumSize) {
                    throw LockboxApiException.bad(
                            "ARTIFACT_TOO_LARGE",
                            "Lockbox artifact exceeds "
                                    + "its configured limit."
                    );
                }

                output.write(
                        buffer,
                        0,
                        count
                );
            }
        }
    }

    private static byte[] readExact(
            Path path,
            long maximumSize
    ) throws IOException {

        long size = Files.size(path);

        if (size > maximumSize
                || size > Integer.MAX_VALUE) {
            throw LockboxApiException.bad(
                    "ARTIFACT_TOO_LARGE",
                    "Lockbox artifact exceeds "
                            + "its configured limit."
            );
        }

        return Files.readAllBytes(path);
    }

    private static byte[] calculateSha3_512(
            Path path
    ) throws Exception {

        MessageDigest digest =
                MessageDigest.getInstance(
                        "SHA3-512"
                );

        try (InputStream input =
                     Files.newInputStream(path)) {

            byte[] buffer =
                    new byte[1024 * 1024];

            for (
                    int count;
                    (count = input.read(buffer)) != -1;
            ) {
                digest.update(
                        buffer,
                        0,
                        count
                );
            }
        }

        return digest.digest();
    }

    private static byte[] signingTranscript(
            byte[] manifest
    ) {
        byte[] transcript =
                new byte[
                        SIGNING_DOMAIN.length
                                + manifest.length
                        ];

        System.arraycopy(
                SIGNING_DOMAIN,
                0,
                transcript,
                0,
                SIGNING_DOMAIN.length
        );

        System.arraycopy(
                manifest,
                0,
                transcript,
                SIGNING_DOMAIN.length,
                manifest.length
        );

        return transcript;
    }

    private void uploadObject(
            String objectKey,
            Path source,
            LockboxObjectStorage.ArtifactType artifactType,
            List<String> uploadedObjects
    ) throws Exception {

        storage.upload(
                objectKey,
                source,
                artifactType
        );

        uploadedObjects.add(objectKey);
    }

    private void registerRollbackCleanup(
            List<String> uploadedObjects
    ) {
        TransactionSynchronizationManager
                .registerSynchronization(
                        new TransactionSynchronization() {
                            @Override
                            public void afterCompletion(
                                    int status
                            ) {
                                if (status
                                        != STATUS_COMMITTED) {
                                    cleanupUploadedObjects(
                                            List.copyOf(
                                                    uploadedObjects
                                            ),
                                            null
                                    );
                                }
                            }
                        }
                );
    }

    private void cleanupUploadedObjects(
            List<String> objectKeys,
            Exception originalFailure
    ) {
        for (String objectKey : objectKeys) {
            try {
                storage.delete(objectKey);
            } catch (Exception cleanupFailure) {
                if (originalFailure != null) {
                    originalFailure.addSuppressed(
                            cleanupFailure
                    );
                }
            }
        }
    }

    private byte[] readBoundedObject(
            String objectKey,
            int maximumSize,
            String artifactName
    ) throws Exception {

        try (InputStream input =
                     storage.download(objectKey)) {

            byte[] bytes =
                    input.readNBytes(
                            maximumSize + 1
                    );

            if (bytes.length == 0) {
                throw LockboxApiException.bad(
                        "INVALID_MANIFEST",
                        "Stored Lockbox "
                                + artifactName
                                + " is empty."
                );
            }

            if (bytes.length > maximumSize) {
                throw LockboxApiException.bad(
                        "ARTIFACT_TOO_LARGE",
                        "Stored Lockbox "
                                + artifactName
                                + " exceeds its size limit."
                );
            }

            return bytes;
        }
    }

    private byte[] readContainerHeader(
            String objectKey
    ) throws Exception {

        try (InputStream input =
                     storage.download(objectKey)) {

            byte[] preamble =
                    input.readNBytes(
                            CSEMLK03_PREAMBLE_SIZE
                    );

            if (preamble.length
                    != CSEMLK03_PREAMBLE_SIZE) {
                throw LockboxApiException.bad(
                        "MANIFEST_CONTAINER_MISMATCH",
                        "Stored CSEMLK03 preamble "
                                + "is truncated."
                );
            }

            validateCsemlk03Preamble(preamble);

            long unsignedHeaderLength =
                    Integer.toUnsignedLong(
                            ByteBuffer
                                    .wrap(
                                            preamble,
                                            12,
                                            4
                                    )
                                    .order(
                                            ByteOrder.LITTLE_ENDIAN
                                    )
                                    .getInt()
                    );

            if (unsignedHeaderLength
                    < CSEMLK03_PREAMBLE_SIZE
                    || unsignedHeaderLength
                    > MAX_HEADER_SIZE) {
                throw LockboxApiException.bad(
                        "MANIFEST_CONTAINER_MISMATCH",
                        "Stored CSEMLK03 header "
                                + "length is invalid."
                );
            }

            int headerLength =
                    Math.toIntExact(
                            unsignedHeaderLength
                    );

            byte[] header =
                    new byte[headerLength];

            System.arraycopy(
                    preamble,
                    0,
                    header,
                    0,
                    preamble.length
            );

            int remaining =
                    headerLength
                            - CSEMLK03_PREAMBLE_SIZE;

            byte[] rest =
                    input.readNBytes(remaining);

            if (rest.length != remaining) {
                throw LockboxApiException.bad(
                        "MANIFEST_CONTAINER_MISMATCH",
                        "Stored CSEMLK03 header "
                                + "is truncated."
                );
            }

            System.arraycopy(
                    rest,
                    0,
                    header,
                    CSEMLK03_PREAMBLE_SIZE,
                    rest.length
            );

            return header;
        }
    }

    private static void validateCsemlk03Preamble(
            byte[] preamble
    ) {
        byte[] expectedMagic =
                "CSEMLK03".getBytes(
                        StandardCharsets.US_ASCII
                );

        byte[] actualMagic =
                Arrays.copyOfRange(
                        preamble,
                        0,
                        8
                );

        if (!Arrays.equals(
                actualMagic,
                expectedMagic
        )) {
            throw LockboxApiException.bad(
                    "UNSUPPORTED_LOCKBOX_VERSION",
                    "Stored object is not "
                            + "a CSEMLK03 container."
            );
        }

        ByteBuffer buffer =
                ByteBuffer
                        .wrap(preamble)
                        .order(ByteOrder.LITTLE_ENDIAN);

        buffer.position(8);

        int version =
                Short.toUnsignedInt(
                        buffer.getShort()
                );

        int preambleSize =
                Short.toUnsignedInt(
                        buffer.getShort()
                );

        if (version != 3
                || preambleSize
                != CSEMLK03_PREAMBLE_SIZE) {
            throw LockboxApiException.bad(
                    "UNSUPPORTED_LOCKBOX_VERSION",
                    "Stored CSEMLK03 preamble "
                            + "is unsupported."
            );
        }
    }

    private static boolean allZero(
            byte[] bytes
    ) {
        int combined = 0;

        for (byte value : bytes) {
            combined |= value;
        }

        return combined == 0;
    }

    private static void throwDuplicate() {
        throw new LockboxApiException(
                "DUPLICATE_LOCKBOX_FILE",
                HttpStatus.CONFLICT,
                "This Lockbox file revision "
                        + "already exists."
        );
    }

    private static void validateNames(
            MultipartFile container,
            MultipartFile manifest,
            MultipartFile signature,
            UUID clientFileId
    ) {
        checkName(
                container,
                clientFileId + ".fdcse"
        );

        checkName(
                manifest,
                clientFileId + ".fdmanifest"
        );

        checkName(
                signature,
                clientFileId + ".fdsig"
        );
    }

    private static void checkName(
            MultipartFile part,
            String expectedName
    ) {
        String suppliedName =
                part.getOriginalFilename();

        if (suppliedName != null
                && !suppliedName.isBlank()
                && !suppliedName.equalsIgnoreCase(
                expectedName
        )) {
            throw LockboxApiException.bad(
                    "INVALID_MANIFEST",
                    "Multipart artifact filename "
                            + "does not match the signed file UUID."
            );
        }
    }

    private static void deleteTree(
            Path directory
    ) {
        if (directory == null) {
            return;
        }

        try (
                var paths =
                        Files.walk(directory)
        ) {
            paths.sorted(
                            Comparator.reverseOrder()
                    )
                    .forEach(path -> {
                        try {
                            Files.deleteIfExists(path);
                        } catch (IOException ignored) {
                            // Temporary-file cleanup must not hide
                            // the original request result.
                        }
                    });
        } catch (IOException ignored) {
            // Temporary-file cleanup must not hide
            // the original request result.
        }
    }

    @Transactional(readOnly = true)
    public LockboxPrivateMetadataListResponse
    privateMetadataList() throws Exception {

        User user = access.currentUser();

        List<LockboxFile> ownedFiles =
                lockboxFiles
                        .findAllByProfileUserIdAndFileDeletedFalseAndFilePermanentlyDeletedFalseOrderByCreatedAtDesc(
                                user.getId()
                        );

        List<LockboxPrivateMetadataResponse> responses =
                new ArrayList<>(
                        ownedFiles.size()
                );

        for (LockboxFile file : ownedFiles) {
            responses.add(
                    buildPrivateMetadata(file)
            );
        }

        return new LockboxPrivateMetadataListResponse(
                responses
        );
    }

    private LockboxPrivateMetadataResponse
    buildPrivateMetadata(
            LockboxFile file
    ) throws Exception {
        LockboxFileRevision revision = currentRevision(file);

        byte[] manifest = readBoundedObject(
                revision.getManifestObjectKey(),
                MAX_MANIFEST_SIZE,
                "manifest"
        );

        byte[] signature = readBoundedObject(
                revision.getSignatureObjectKey(),
                MAX_SIGNATURE_SIZE,
                "signature"
        );

        byte[] encryptedHeader =
                readContainerHeader(
                        revision.getContainerObjectKey()
                );

        return new LockboxPrivateMetadataResponse(
                file.getId(),
                file.getClientFileId(),
                revision.getRevision(),
                Base64.getEncoder()
                        .encodeToString(manifest),
                Base64.getEncoder()
                        .encodeToString(signature),
                Base64.getEncoder()
                        .encodeToString(encryptedHeader)
        );
    }

    private LockboxFileRevision currentRevision(LockboxFile file) {
        return revisions.findByLockboxFileIdAndRevision(file.getId(), file.getCurrentRevision())
                .orElseThrow(() -> new IllegalStateException("Current Lockbox revision is missing."));
    }
}
