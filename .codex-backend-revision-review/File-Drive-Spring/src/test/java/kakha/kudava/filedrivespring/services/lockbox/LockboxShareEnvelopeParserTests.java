package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class LockboxShareEnvelopeParserTests {
    private final LockboxShareEnvelopeParser parser = new LockboxShareEnvelopeParser();
    private static final UUID SHARE = UUID.fromString("11223344-5566-4788-99aa-bbccddeeff00");
    private static final UUID FILE = UUID.fromString("01234567-89ab-4cde-8fab-0123456789ab");
    private static final UUID OWNER = UUID.fromString("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee");
    private static final UUID RECIPIENT = UUID.fromString("12345678-1234-4abc-9def-123456789abc");

    @Test void fixedVectorParsesEveryOffset() {
        byte[] p=valid(); var c=parser.parse(p);
        assertEquals(SHARE,c.shareUuid()); assertEquals(FILE,c.clientFileUuid()); assertEquals(7,c.revision());
        assertArrayEquals(fill(64,(byte)3),c.containerHash()); assertEquals(OWNER,c.ownerPublicUuid());
        assertEquals(RECIPIENT,c.recipientPublicUuid()); assertArrayEquals(fill(32,(byte)6),c.recipientKeyId());
        assertEquals(1,c.permission()); assertEquals(123456789,c.expiresAtUnixSeconds());
        assertEquals(1568,le32(p,234)); assertEquals(48,le32(p,238));
    }
    @Test void rejectsWrongLengthsAndTrailingBytes(){reject(Arrays.copyOf(valid(),1857));reject(Arrays.copyOf(valid(),1859));}
    @Test void rejectsMagicVersionAndSuite(){mutate(0);mutate16(8,2);mutate16(10,2);}
    @Test void rejectsInnerLengths(){mutate32(234,1567);mutate32(238,47);}
    @Test void rejectsZeroUuids(){zero(12,16);zero(28,16);zero(116,16);zero(132,16);}
    @Test void acceptsEqualOwnerAndRecipientUuidsForSelfSharing(){
        byte[] p=valid();
        System.arraycopy(p,116,p,132,16);
        var context=parser.parse(p);
        assertEquals(context.ownerPublicUuid(),context.recipientPublicUuid());
    }
    @Test void rejectsMalformedUuidEncoding(){byte[]p=valid();p[12+6]&=0x0f;reject(p);}
    @Test void rejectsZeroRevisionHashAndKeyId(){zero(44,8);zero(52,64);zero(148,32);}
    @Test void rejectsUnsupportedPermission(){mutate16(180,2);}
    @Test void returnedArraysAreDefensiveCopies(){var c=parser.parse(valid());byte[]h=c.containerHash();h[0]=0;assertEquals(3,c.containerHash()[0]);}
    private void mutate(int o){byte[]p=valid();p[o]^=1;reject(p);} private void mutate16(int o,int v){byte[]p=valid();put(p,o,2,v);reject(p);} private void mutate32(int o,int v){byte[]p=valid();put(p,o,4,v);reject(p);} private void zero(int o,int n){byte[]p=valid();Arrays.fill(p,o,o+n,(byte)0);reject(p);}
    private void reject(byte[]p){LockboxApiException e=assertThrows(LockboxApiException.class,()->parser.parse(p));assertEquals("INVALID_LOCKBOX_SHARE",e.getCode());}
    private static byte[] valid(){byte[]p=new byte[1858];System.arraycopy("FDSHENV1".getBytes(),0,p,0,8);put(p,8,2,1);put(p,10,2,1);uuid(p,12,SHARE);uuid(p,28,FILE);put(p,44,8,7);Arrays.fill(p,52,116,(byte)3);uuid(p,116,OWNER);uuid(p,132,RECIPIENT);Arrays.fill(p,148,180,(byte)6);put(p,180,2,1);put(p,182,8,123456789);put(p,234,4,1568);put(p,238,4,48);return p;}
    private static void uuid(byte[]p,int o,UUID u){ByteBuffer.wrap(p,o,16).order(ByteOrder.BIG_ENDIAN).putLong(u.getMostSignificantBits()).putLong(u.getLeastSignificantBits());}
    private static void put(byte[]p,int o,int n,long v){ByteBuffer b=ByteBuffer.wrap(p,o,n).order(ByteOrder.LITTLE_ENDIAN);if(n==2)b.putShort((short)v);else if(n==4)b.putInt((int)v);else b.putLong(v);}
    private static long le32(byte[]p,int o){return Integer.toUnsignedLong(ByteBuffer.wrap(p,o,4).order(ByteOrder.LITTLE_ENDIAN).getInt());}
    private static byte[] fill(int n,byte v){byte[]x=new byte[n];Arrays.fill(x,v);return x;}
}
