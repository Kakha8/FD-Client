package kakha.kudava.filedrivespring.dto.lockbox;

public record LockboxCreateShareRequest(
        Long fileId,
        Long revision,
        String envelope,
        String ownerSigningKeyId,
        String ownerSignature
) {
    public LockboxCreateShareRequest(Long fileId,String envelope,String ownerSigningKeyId,String ownerSignature){this(fileId,null,envelope,ownerSigningKeyId,ownerSignature);}
}
