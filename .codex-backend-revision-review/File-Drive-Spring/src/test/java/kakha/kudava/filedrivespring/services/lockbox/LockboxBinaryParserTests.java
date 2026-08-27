package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import org.junit.jupiter.api.Test;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

class LockboxBinaryParserTests {
    @Test void manifestUsesExactRustOffsetsAndRejectsBoundaries(){
        UUID file=UUID.fromString("7f34b03e-8e51-43d1-a225-1768fd7953f8"),device=UUID.fromString("11111111-2222-4333-8444-555555555555");
        ByteBuffer b=ByteBuffer.allocate(264).order(ByteOrder.LITTLE_ENDIAN);b.put("FDMAN003".getBytes(StandardCharsets.US_ASCII));b.putShort((short)1).putShort((short)3).putShort((short)1).putShort((short)1);putUuid(b,file);b.putLong(1).putLong(99);b.put(new byte[64]);b.put(fill(32,(byte)3));b.put(fill(32,(byte)4));putUuid(b,device);b.putLong(123);b.put(new byte[64]);
        var parsed=new LockboxManifestParser().parse(b.array());assertEquals(file,parsed.clientFileId());assertEquals(1,parsed.revision());assertEquals(99,parsed.containerSize());assertEquals(device,parsed.deviceUuid());assertArrayEquals(fill(32,(byte)3),parsed.encryptionKeyId());
        assertThrows(LockboxApiException.class,()->new LockboxManifestParser().parse(java.util.Arrays.copyOf(b.array(),263)));
        assertThrows(LockboxApiException.class,()->new LockboxManifestParser().parse(java.util.Arrays.copyOf(b.array(),265)));
    }
    @Test void signatureUsesExactRustLengthAndRejectsTrailingAndTruncated(){
        ByteBuffer b=ByteBuffer.allocate(4675).order(ByteOrder.LITTLE_ENDIAN);b.put("FDSIG001".getBytes(StandardCharsets.US_ASCII)).putShort((short)1).putShort((short)1).put(fill(32,(byte)8)).putInt(4627).put(new byte[4627]);
        var parsed=new LockboxSignatureRecordParser().parse(b.array());assertArrayEquals(fill(32,(byte)8),parsed.signingKeyId());assertEquals(4627,parsed.signature().length);
        assertThrows(LockboxApiException.class,()->new LockboxSignatureRecordParser().parse(java.util.Arrays.copyOf(b.array(),4674)));
        assertThrows(LockboxApiException.class,()->new LockboxSignatureRecordParser().parse(java.util.Arrays.copyOf(b.array(),4676)));
    }
    private static byte[] fill(int n,byte v){byte[] x=new byte[n];java.util.Arrays.fill(x,v);return x;}
    private static void putUuid(ByteBuffer b,UUID u){b.order(ByteOrder.BIG_ENDIAN).putLong(u.getMostSignificantBits()).putLong(u.getLeastSignificantBits()).order(ByteOrder.LITTLE_ENDIAN);}
}
