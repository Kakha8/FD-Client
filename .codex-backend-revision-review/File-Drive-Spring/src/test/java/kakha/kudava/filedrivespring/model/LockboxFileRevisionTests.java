package kakha.kudava.filedrivespring.model;

import org.junit.jupiter.api.Test;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class LockboxFileRevisionTests {
    @Test void logicalRevisionAdvancesContiguously(){
        LockboxFile file=new LockboxFile(mock(FileMetaData.class),mock(LockboxProfile.class),UUID.randomUUID(),1);
        file.advanceToRevision(1,2);
        assertEquals(2,file.getCurrentRevision());
        assertThrows(IllegalStateException.class,()->file.advanceToRevision(1,2));
        assertThrows(IllegalArgumentException.class,()->file.advanceToRevision(2,4));
    }
    @Test void revisionCryptographicFieldsAreDefensivelyImmutable(){
        byte[] hash=new byte[64],encryption=new byte[32],signing=new byte[32];hash[0]=1;
        LockboxFile logical=new LockboxFile(mock(FileMetaData.class),mock(LockboxProfile.class),UUID.randomUUID(),1);
        LockboxFileRevision revision=new LockboxFileRevision(logical,1,3,1,10,hash,encryption,signing,UUID.randomUUID(),1,1,"c","m","s");
        hash[0]=9;byte[] returned=revision.getContainerHash();returned[0]=8;
        assertEquals(1,revision.getContainerHash()[0]);
        assertThrows(IllegalArgumentException.class,()->new LockboxFileRevision(logical,0,3,1,10,new byte[64],new byte[32],new byte[32],UUID.randomUUID(),1,1,"c2","m2","s2"));
    }
}
