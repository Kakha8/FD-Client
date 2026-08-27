package kakha.kudava.filedrivespring.services.lockbox;

import kakha.kudava.filedrivespring.exceptions.LockboxApiException;
import org.springframework.stereotype.Component;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;

@Component
public final class LockboxShareEnvelopeParser {
    public static final int PACKAGE_LENGTH = 1858;
    private static final byte[] MAGIC = "FDSHENV1".getBytes(StandardCharsets.US_ASCII);

    public ParsedContext parse(byte[] packageBytes) {
        if (packageBytes == null || packageBytes.length != PACKAGE_LENGTH) invalid();
        ByteBuffer buffer = ByteBuffer.wrap(packageBytes.clone()).asReadOnlyBuffer().order(ByteOrder.LITTLE_ENDIAN);
        byte[] magic = new byte[8]; buffer.get(magic);
        if (!Arrays.equals(magic, MAGIC) || u16(buffer) != 1 || u16(buffer) != 1) invalid();
        UUID shareUuid = uuid(buffer), clientFileUuid = uuid(buffer);
        long revision = buffer.getLong();
        byte[] containerHash = bytes(buffer, 64);
        UUID ownerPublicUuid = uuid(buffer), recipientPublicUuid = uuid(buffer);
        byte[] recipientKeyId = bytes(buffer, 32);
        int permission = u16(buffer);
        long expiresAt = buffer.getLong();
        buffer.position(234);
        long kemLength = Integer.toUnsignedLong(buffer.getInt());
        long wrappedLength = Integer.toUnsignedLong(buffer.getInt());
        if (revision <= 0 || allZero(containerHash) || allZero(recipientKeyId)
                || permission != 1
                || kemLength != 1568 || wrappedLength != 48 || buffer.remaining() != 1616) invalid();
        return new ParsedContext(shareUuid, clientFileUuid, revision, containerHash,
                ownerPublicUuid, recipientPublicUuid, recipientKeyId, permission, expiresAt);
    }

    private static int u16(ByteBuffer b) { return Short.toUnsignedInt(b.getShort()); }
    private static byte[] bytes(ByteBuffer b, int n) { byte[] v = new byte[n]; b.get(v); return v; }
    private static UUID uuid(ByteBuffer b) { byte[] v = bytes(b, 16); if (allZero(v)) invalid(); ByteBuffer u = ByteBuffer.wrap(v).order(ByteOrder.BIG_ENDIAN); UUID value = new UUID(u.getLong(), u.getLong()); if (value.variant() != 2 || value.version() < 1 || value.version() > 8) invalid(); return value; }
    private static boolean allZero(byte[] v) { int x = 0; for (byte b : v) x |= b; return x == 0; }
    private static void invalid() { throw LockboxApiException.bad("INVALID_LOCKBOX_SHARE", "The share envelope is invalid."); }

    public record ParsedContext(UUID shareUuid, UUID clientFileUuid, long revision, byte[] containerHash,
            UUID ownerPublicUuid, UUID recipientPublicUuid, byte[] recipientKeyId,
            int permission, long expiresAtUnixSeconds) {
        public ParsedContext { containerHash = containerHash.clone(); recipientKeyId = recipientKeyId.clone(); }
        @Override public byte[] containerHash() { return containerHash.clone(); }
        @Override public byte[] recipientKeyId() { return recipientKeyId.clone(); }
    }
}
