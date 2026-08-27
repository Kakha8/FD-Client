package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import kakha.kudava.filedrivespring.model.*;
import kakha.kudava.filedrivespring.repository.*;
import kakha.kudava.filedrivespring.services.ResourceAccessService;
import kakha.kudava.filedrivespring.services.objects.RootFolderService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.mock.web.MockMultipartFile;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.mockito.ArgumentCaptor;

class LockboxRevisionHardeningTests {
    @AfterEach void clearSynchronization(){if(TransactionSynchronizationManager.isSynchronizationActive())TransactionSynchronizationManager.clearSynchronization();}

    @Test void suspendedProfileIsRejectedBeforeStagingOrStorageAccess() throws Exception {
        Fixture f=new Fixture();when(f.profile.getStatus()).thenReturn(LockboxProfile.Status.SUSPENDED);
        LockboxApiException error=assertThrows(LockboxApiException.class,()->f.service.uploadRevision(10L,1,null,null,null));
        assertEquals(HttpStatus.FORBIDDEN,error.getStatus());assertEquals("LOCKBOX_NOT_ENABLED",error.getCode());
        verifyNoInteractions(f.storage,f.revisions);
    }

    @Test void validSecondRevisionUsesExactPreviousManifestHashAndAdvancesLogicalFile() throws Exception {
        Fixture f=new Fixture();UUID clientFileId=UUID.randomUUID(),deviceId=UUID.randomUUID();
        byte[] previousManifest="exact-stored-manifest-v1".getBytes();byte[] containerBytes="encrypted-container-v2".getBytes();
        byte[] containerHash=MessageDigest.getInstance("SHA3-512").digest(containerBytes);
        byte[] previousHash=MessageDigest.getInstance("SHA3-512").digest(previousManifest);
        byte[] encryptionId=new byte[32],signingId=new byte[32];encryptionId[0]=1;signingId[0]=2;
        LockboxFileRevision previous=revision("r1");when(previous.getManifestObjectKey()).thenReturn("r1-manifest");
        when(f.logical.getClientFileId()).thenReturn(clientFileId);when(f.logical.getCurrentRevision()).thenReturn(1L);
        when(f.revisions.findByLockboxFileIdAndRevision(10L,1L)).thenReturn(Optional.of(previous));
        when(f.storage.download("r1-manifest")).thenReturn(new ByteArrayInputStream(previousManifest));
        when(f.manifests.parse(any())).thenReturn(new LockboxManifestParser.Manifest(clientFileId,2,containerBytes.length,containerHash,encryptionId,signingId,deviceId,java.time.Instant.now(),previousHash,3,1));
        when(f.signatures.parse(any())).thenReturn(new LockboxSignatureRecordParser.SignatureRecord(signingId,new byte[4627]));
        LockboxDevice device=mock(LockboxDevice.class);when(device.getStatus()).thenReturn(LockboxDevice.Status.ACTIVE);when(device.getDeviceUuid()).thenReturn(deviceId);
        LockboxKey signingKey=mock(LockboxKey.class),encryptionKey=mock(LockboxKey.class);when(signingKey.getKeyId()).thenReturn(signingId);when(signingKey.getDevice()).thenReturn(device);when(signingKey.getPublicKey()).thenReturn(new byte[1]);when(encryptionKey.getKeyId()).thenReturn(encryptionId);
        when(f.keys.findAllByDeviceProfileIdAndRoleAndStatus(any(),eq(LockboxKey.Role.SIGNING),eq(LockboxKey.Status.ACTIVE))).thenReturn(List.of(signingKey));
        when(f.keys.findAllByDeviceProfileIdAndRoleAndStatus(any(),eq(LockboxKey.Role.ENCRYPTION),eq(LockboxKey.Status.ACTIVE))).thenReturn(List.of(encryptionKey));
        when(f.containers.validate(any(),eq((long)containerBytes.length))).thenReturn(new LockboxV3ContainerValidator.Container(clientFileId,encryptionId,1,1_048_576,1));
        when(f.revisions.saveAndFlush(any())).thenAnswer(invocation->invocation.getArgument(0));
        TransactionSynchronizationManager.initSynchronization();
        var response=f.service.uploadRevision(10L,1,
                new MockMultipartFile("container",clientFileId+".fdcse","application/octet-stream",containerBytes),
                new MockMultipartFile("manifest",clientFileId+".fdmanifest","application/octet-stream",new byte[]{3}),
                new MockMultipartFile("signature",clientFileId+".fdsig","application/octet-stream",new byte[]{4}));
        assertEquals(10L,response.id());assertEquals(clientFileId,response.clientFileId());assertEquals(2,response.revision());
        verify(f.logical).advanceToRevision(1,2);verify(f.logicalFiles).saveAndFlush(f.logical);
        ArgumentCaptor<LockboxFileRevision> saved=ArgumentCaptor.forClass(LockboxFileRevision.class);verify(f.revisions).saveAndFlush(saved.capture());
        assertEquals(2,saved.getValue().getRevision());assertTrue(saved.getValue().getContainerObjectKey().contains("/2/requests/"));
        verify(f.storage,never()).delete(startsWith("r1-"));
    }

    @Test void staleRevisionConflictsBeforeArtifactOrStorageAccess() throws Exception {
        Fixture f=new Fixture();when(f.logical.getCurrentRevision()).thenReturn(2L);
        LockboxApiException error=assertThrows(LockboxApiException.class,()->f.service.uploadRevision(10L,1,null,null,null));
        assertEquals(HttpStatus.CONFLICT,error.getStatus());assertEquals("LOCKBOX_REVISION_CONFLICT",error.getCode());verifyNoInteractions(f.storage,f.revisions);
    }

    @Test void deletionRunsAllStorageCleanupOnlyAfterCommit() throws Exception {
        Fixture f=new Fixture();LockboxFileRevision r1=revision("r1"),r2=revision("r2");
        when(f.revisions.findAllByLockboxFileIdOrderByRevisionDesc(10L)).thenReturn(List.of(r2,r1));
        doThrow(new RuntimeException("orphan")).when(f.storage).delete("r2-container");
        TransactionSynchronizationManager.initSynchronization();
        f.service.deleteLockboxFile(10L);
        verify(f.files).saveAndFlush(f.metadata);verifyNoInteractions(f.storage);
        List<TransactionSynchronization> synchronizations=TransactionSynchronizationManager.getSynchronizations();
        assertEquals(1,synchronizations.size());synchronizations.getFirst().afterCommit();
        for(String prefix:List.of("r2","r1"))for(String artifact:List.of("container","manifest","signature"))verify(f.storage).delete(prefix+"-"+artifact);
    }

    @Test void rollbackPerformsNoStorageDeletionAndRepeatedDeleteIsIdempotent() throws Exception {
        Fixture f=new Fixture();LockboxFileRevision r1=revision("r1");
        when(f.revisions.findAllByLockboxFileIdOrderByRevisionDesc(10L)).thenReturn(List.of(r1));
        TransactionSynchronizationManager.initSynchronization();f.service.deleteLockboxFile(10L);
        TransactionSynchronizationManager.clearSynchronization();verifyNoInteractions(f.storage);
        reset(f.revisions);when(f.metadata.isPermanentlyDeleted()).thenReturn(true);
        f.service.deleteLockboxFile(10L);verifyNoInteractions(f.revisions,f.storage);
    }

    @Test void tombstonedFilesCannotListOrDownloadCurrentOrHistoricalArtifacts() throws Exception {
        Fixture f=new Fixture();when(f.metadata.isDeleted()).thenReturn(true);
        assertNotFound(assertThrows(LockboxApiException.class,()->f.service.revisionHistory(10L)));
        assertNotFound(assertThrows(LockboxApiException.class,()->f.service.openDownload(10L,LockboxObjectStorage.ArtifactType.CONTAINER)));
        assertNotFound(assertThrows(LockboxApiException.class,()->f.service.openRevisionDownload(10L,1,LockboxObjectStorage.ArtifactType.CONTAINER)));
        verifyNoInteractions(f.storage);
    }

    private static void assertNotFound(LockboxApiException error){assertEquals(HttpStatus.NOT_FOUND,error.getStatus());assertEquals("LOCKBOX_FILE_NOT_FOUND",error.getCode());}
    private static LockboxFileRevision revision(String prefix){LockboxFileRevision r=mock(LockboxFileRevision.class);when(r.getContainerObjectKey()).thenReturn(prefix+"-container");when(r.getManifestObjectKey()).thenReturn(prefix+"-manifest");when(r.getSignatureObjectKey()).thenReturn(prefix+"-signature");return r;}

    private static final class Fixture{
        final LockboxManifestParser manifests=mock(LockboxManifestParser.class);final LockboxSignatureRecordParser signatures=mock(LockboxSignatureRecordParser.class);final LockboxV3ContainerValidator containers=mock(LockboxV3ContainerValidator.class);
        final LockboxObjectStorage storage=mock(LockboxObjectStorage.class);final FileMetaDataRepository files=mock(FileMetaDataRepository.class);
        final LockboxFileRepository logicalFiles=mock(LockboxFileRepository.class);final LockboxFileRevisionRepository revisions=mock(LockboxFileRevisionRepository.class);
        final LockboxKeyRepository keys=mock(LockboxKeyRepository.class);
        final ResourceAccessService access=mock(ResourceAccessService.class);final User user=mock(User.class);final LockboxFile logical=mock(LockboxFile.class);
        final FileMetaData metadata=mock(FileMetaData.class);final LockboxProfile profile=mock(LockboxProfile.class);
        final LockboxService service=new LockboxService(manifests,signatures,containers,mock(LockboxSignatureVerifier.class),storage,files,mock(FolderRepository.class),logicalFiles,revisions,keys,mock(LockboxProfileRepository.class),mock(RootFolderService.class),access,1024,1024,1024);
        Fixture(){when(access.currentUser()).thenReturn(user);when(user.getId()).thenReturn(1L);when(logicalFiles.findByIdAndProfileUserId(10L,1L)).thenReturn(Optional.of(logical));when(logicalFiles.findForUpdateByIdAndProfileUserId(10L,1L)).thenReturn(Optional.of(logical));when(logical.getId()).thenReturn(10L);when(logical.getFile()).thenReturn(metadata);when(logical.getProfile()).thenReturn(profile);when(profile.getId()).thenReturn(5L);when(profile.getStatus()).thenReturn(LockboxProfile.Status.ENABLED);}
    }
}
