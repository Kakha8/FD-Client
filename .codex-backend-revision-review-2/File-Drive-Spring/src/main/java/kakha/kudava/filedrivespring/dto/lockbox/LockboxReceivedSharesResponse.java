package kakha.kudava.filedrivespring.dto.lockbox;

import java.util.List;

public record LockboxReceivedSharesResponse(
        List<LockboxReceivedShareResponse> shares
) {
    public LockboxReceivedSharesResponse {
        shares = List.copyOf(shares);
    }
}