package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import org.springframework.stereotype.Component;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@Component
public class LockboxSignatureRecordParser {
    public static final int SIGNATURE_LENGTH=4627, LENGTH=4675;
    public record SignatureRecord(byte[] signingKeyId,byte[] signature) {}
    public SignatureRecord parse(byte[] bytes){
        try{
            if(bytes==null||bytes.length!=LENGTH) fail();
            ByteBuffer b=ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN); byte[] magic=new byte[8];b.get(magic);
            if(!Arrays.equals(magic,"FDSIG001".getBytes(StandardCharsets.US_ASCII))||Short.toUnsignedInt(b.getShort())!=1||Short.toUnsignedInt(b.getShort())!=1) fail();
            byte[] id=new byte[32];b.get(id); long len=Integer.toUnsignedLong(b.getInt()); if(len!=SIGNATURE_LENGTH) fail();
            byte[] signature=new byte[SIGNATURE_LENGTH];b.get(signature);if(b.hasRemaining())fail();return new SignatureRecord(id,signature);
        }catch(LockboxApiException e){throw e;}catch(RuntimeException e){throw new LockboxApiException("INVALID_SIGNATURE_RECORD",org.springframework.http.HttpStatus.BAD_REQUEST,"Signature record is malformed.");}
    }
    private static void fail(){throw new LockboxApiException("INVALID_SIGNATURE_RECORD",org.springframework.http.HttpStatus.BAD_REQUEST,"Signature record is malformed.");}
}
