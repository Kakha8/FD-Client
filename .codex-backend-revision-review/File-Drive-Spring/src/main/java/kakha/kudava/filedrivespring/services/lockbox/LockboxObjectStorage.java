package kakha.kudava.filedrivespring.services.lockbox;

import java.io.InputStream;
import java.nio.file.Path;

public interface LockboxObjectStorage {

    void upload(
            String objectKey,
            Path source,
            ArtifactType artifactType
    ) throws Exception;

    InputStream download(String objectKey) throws Exception;

    void delete(String objectKey) throws Exception;

    enum ArtifactType {
        CONTAINER("application/x-filedrive-csemlk03"),
        MANIFEST("application/x-filedrive-lockbox-manifest"),
        SIGNATURE("application/x-filedrive-lockbox-signature");
        private final String contentType;
        ArtifactType(String contentType){this.contentType=contentType;}
        public String contentType(){return contentType;}
    }

    long size(
            String objectKey
    ) throws Exception;
}
