package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import org.springframework.stereotype.Component;
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

@Component
public class LockboxV3ContainerValidator {
    public static final int CHUNK_SIZE=1_048_576, MAX_HEADER=1_048_576;
    public record Container(UUID clientFileId,byte[] encryptionKeyId,long chunkCount,int chunkSize,int suiteId) {}
    public Container validate(Path path,long actualSize){
        try(InputStream in=Files.newInputStream(path)){
            byte[] pre=in.readNBytes(32); if(pre.length!=32) invalid(); ByteBuffer p=ByteBuffer.wrap(pre).order(ByteOrder.LITTLE_ENDIAN);
            byte[] magic=new byte[8];p.get(magic); if(!Arrays.equals(magic,"CSEMLK03".getBytes(StandardCharsets.US_ASCII))) unsupported();
            if(Short.toUnsignedInt(p.getShort())!=3||Short.toUnsignedInt(p.getShort())!=32) unsupported();
            long headerLen=Integer.toUnsignedLong(p.getInt()); int suite=Short.toUnsignedInt(p.getShort()); int flags=Short.toUnsignedInt(p.getShort());
            long chunkSize=Integer.toUnsignedLong(p.getInt()), chunks=Integer.toUnsignedLong(p.getInt()); int sections=Short.toUnsignedInt(p.getShort()),reserved=Short.toUnsignedInt(p.getShort());
            if(headerLen<32||headerLen>MAX_HEADER||suite!=1||flags!=7||chunkSize!=CHUNK_SIZE||chunks<1||sections!=3||reserved!=0) invalid();
            long expected=Math.addExact(headerLen,Math.multiplyExact(chunks,CHUNK_SIZE+16L)); if(expected!=actualSize) throw LockboxApiException.bad("CONTAINER_SIZE_MISMATCH","Container size does not match its header.");
            byte[] rest=in.readNBytes(Math.toIntExact(headerLen-32));if(rest.length!=headerLen-32)invalid(); ByteBuffer b=ByteBuffer.wrap(rest).order(ByteOrder.LITTLE_ENDIAN);
            byte[] content=section(b,1,64); UUID file=uuid(content,0); if(u16(content,56)!=16||u16(content,58)!=16||u32(content,60)!=0)invalid();
            byte[] envelope=section(b,2,1708); if(u16(envelope,32)!=1||u16(envelope,34)!=1||u16(envelope,36)!=1||u16(envelope,38)!=0||u32(envelope,84)!=1568||u32(envelope,88)!=48)invalid(); byte[] key=Arrays.copyOfRange(envelope,0,32);
            byte[] metadata=section(b,3,-1); if(metadata.length<32||metadata.length>65568||u32(metadata,12)!=metadata.length-16L)invalid(); if(b.hasRemaining())invalid();
            return new Container(file,key,chunks,(int)chunkSize,suite);
        }catch(LockboxApiException e){throw e;}catch(IOException|RuntimeException e){throw LockboxApiException.bad("INVALID_MANIFEST","Container structure is malformed.");}
    }
    private static byte[] section(ByteBuffer b,int type,int exact){if(b.remaining()<8)invalid();if(Short.toUnsignedInt(b.getShort())!=type||Short.toUnsignedInt(b.getShort())!=1)invalid();long n=Integer.toUnsignedLong(b.getInt());if(n>b.remaining()||(exact>=0&&n!=exact))invalid();byte[] x=new byte[(int)n];b.get(x);return x;}
    private static int u16(byte[]x,int o){return Short.toUnsignedInt(ByteBuffer.wrap(x,o,2).order(ByteOrder.LITTLE_ENDIAN).getShort());}
    private static long u32(byte[]x,int o){return Integer.toUnsignedLong(ByteBuffer.wrap(x,o,4).order(ByteOrder.LITTLE_ENDIAN).getInt());}
    private static UUID uuid(byte[]x,int o){ByteBuffer b=ByteBuffer.wrap(x,o,16).order(ByteOrder.BIG_ENDIAN);return new UUID(b.getLong(),b.getLong());}
    private static void invalid(){throw LockboxApiException.bad("MANIFEST_CONTAINER_MISMATCH","Container structure is invalid.");}
    private static void unsupported(){throw LockboxApiException.bad("UNSUPPORTED_LOCKBOX_VERSION","Only CSEMLK03 suite 1 is supported.");}
}
