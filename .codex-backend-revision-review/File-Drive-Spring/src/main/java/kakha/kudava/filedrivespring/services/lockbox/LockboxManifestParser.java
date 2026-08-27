package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import org.springframework.stereotype.Component;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

@Component
public class LockboxManifestParser {
    public static final int LENGTH=264;
    public record Manifest(UUID clientFileId,long revision,long containerSize,byte[] containerHash,
                           byte[] encryptionKeyId,byte[] signingKeyId,UUID deviceUuid,Instant createdAt,
                           byte[] previousManifestHash,int formatVersion,int suiteId) {}
    public Manifest parse(byte[] bytes) {
        try {
            if(bytes==null||bytes.length!=LENGTH) fail();
            ByteBuffer b=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
            byte[] magic=new byte[8]; b.get(magic); if(!Arrays.equals(magic,"FDMAN003".getBytes(java.nio.charset.StandardCharsets.US_ASCII))) fail();
            int manifestVersion=Short.toUnsignedInt(b.getShort()); int format=Short.toUnsignedInt(b.getShort());
            int suite=Short.toUnsignedInt(b.getShort()); int hash=Short.toUnsignedInt(b.getShort());
            if(manifestVersion!=1||format!=3||suite!=1||hash!=1) throw LockboxApiException.bad("UNSUPPORTED_LOCKBOX_VERSION","Unsupported Lockbox manifest version, suite, or hash algorithm.");
            UUID file=uuid(b); long revision=b.getLong(); long size=b.getLong(); if(revision<=0||size<0) fail();
            byte[] digest=get(b,64), enc=get(b,32), sign=get(b,32); UUID device=uuid(b); long millis=b.getLong(); byte[] previous=get(b,64);
            if(b.hasRemaining()) fail();
            return new Manifest(file,revision,size,digest,enc,sign,device,Instant.ofEpochMilli(millis),previous,format,suite);
        } catch(LockboxApiException e){throw e;} catch(RuntimeException e){throw invalid(e);}
    }
    private static UUID uuid(ByteBuffer b){byte[] x=get(b,16); ByteBuffer q=ByteBuffer.wrap(x).order(ByteOrder.BIG_ENDIAN); return new UUID(q.getLong(),q.getLong());}
    private static byte[] get(ByteBuffer b,int n){byte[] x=new byte[n];b.get(x);return x;}
    private static void fail(){throw invalid(null);}
    private static LockboxApiException invalid(Throwable e){return new LockboxApiException("INVALID_MANIFEST",org.springframework.http.HttpStatus.BAD_REQUEST,"Manifest is malformed.");}
}
