package kakha.kudava.filedrivespring.dto.lockbox;

public record LockboxShareResponse(
        String shareId,
        Long fileId,
        long revision,
        String ownerUsername,
        String recipientUsername,
        String recipientKeyId,
        String status
) {
    public LockboxShareResponse(String shareId,Long fileId,String ownerUsername,String recipientUsername,String recipientKeyId,String status){this(shareId,fileId,0,ownerUsername,recipientUsername,recipientKeyId,status);}
}
