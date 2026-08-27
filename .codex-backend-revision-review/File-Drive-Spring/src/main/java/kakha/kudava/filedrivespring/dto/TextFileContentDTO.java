package kakha.kudava.filedrivespring.dto;

public record TextFileContentDTO(
        Long fileId,
        String fileName,
        String contentType,
        String charset,
        Long size,
        String checksum,
        String content
) {
}