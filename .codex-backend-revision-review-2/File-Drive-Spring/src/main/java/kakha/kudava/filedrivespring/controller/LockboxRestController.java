package kakha.kudava.filedrivespring.controller;


import kakha.kudava.filedrivespring.dto.lockbox.LockboxFolderViewResponse;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxPrivateMetadataListResponse;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxUploadResponse;
import kakha.kudava.filedrivespring.dto.lockbox.LockboxRevisionHistoryResponse;
import kakha.kudava.filedrivespring.records.LockboxDownloadResult;
import kakha.kudava.filedrivespring.services.lockbox.LockboxObjectStorage;
import kakha.kudava.filedrivespring.services.lockbox.LockboxService;
import org.springframework.http.CacheControl;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.InputStream;

@RestController
@RequestMapping("/api/lockbox")
public class LockboxRestController {
    static final int STREAM_BUFFER_SIZE = 1024 * 1024;

    private final LockboxService lockboxService;

    public LockboxRestController(LockboxService lockboxService) {
        this.lockboxService = lockboxService;
    }


    @PostMapping(
            value = "/files",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseStatus(HttpStatus.CREATED)
    public LockboxUploadResponse upload(
            @RequestPart("container") MultipartFile container,
            @RequestPart("manifest") MultipartFile manifest,
            @RequestPart("signature") MultipartFile signature,

            @RequestParam(
                    name = "parentFolderId",
                    required = false
            )
            Long parentFolderId
    ) throws Exception {
        return lockboxService.upload(
                container, manifest, signature,
                parentFolderId
        );
    }

    @PutMapping(value="/files/{fileId}/revisions",consumes=MediaType.MULTIPART_FORM_DATA_VALUE,produces=MediaType.APPLICATION_JSON_VALUE)
    public LockboxUploadResponse uploadRevision(@PathVariable Long fileId,@RequestParam long expectedRevision,
            @RequestPart("container") MultipartFile container,@RequestPart("manifest") MultipartFile manifest,
            @RequestPart("signature") MultipartFile signature) throws Exception {
        return lockboxService.uploadRevision(fileId,expectedRevision,container,manifest,signature);
    }

    @GetMapping(value="/files/{fileId}/revisions",produces=MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<LockboxRevisionHistoryResponse> revisionHistory(@PathVariable Long fileId){
        return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(lockboxService.revisionHistory(fileId));
    }

    @GetMapping("/files/{fileId}/revisions/{revision}/container")
    public ResponseEntity<StreamingResponseBody> revisionContainer(@PathVariable Long fileId,@PathVariable long revision) throws Exception{return download(fileId,revision,LockboxObjectStorage.ArtifactType.CONTAINER);}
    @GetMapping("/files/{fileId}/revisions/{revision}/manifest")
    public ResponseEntity<StreamingResponseBody> revisionManifest(@PathVariable Long fileId,@PathVariable long revision) throws Exception{return download(fileId,revision,LockboxObjectStorage.ArtifactType.MANIFEST);}
    @GetMapping("/files/{fileId}/revisions/{revision}/signature")
    public ResponseEntity<StreamingResponseBody> revisionSignature(@PathVariable Long fileId,@PathVariable long revision) throws Exception{return download(fileId,revision,LockboxObjectStorage.ArtifactType.SIGNATURE);}

    /**
     * Returns the current user's Lockbox root and its direct children.
     */
    @GetMapping(
            value = "/folders",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public LockboxFolderViewResponse viewRoot() {
        return lockboxService.viewRoot();
    }

    /**
     * Returns one Lockbox folder and its direct child folders/files.
     */
    @GetMapping(
            value = "/folders/{folderId}",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public LockboxFolderViewResponse viewFolder(
            @PathVariable Long folderId
    ) {
        return lockboxService.viewFolder(folderId);
    }


    @GetMapping("/files/{fileId}/container")
    public ResponseEntity<StreamingResponseBody>
    downloadContainer(
            @PathVariable Long fileId
    ) throws Exception {

        return download(
                fileId,
                LockboxObjectStorage.ArtifactType.CONTAINER
        );
    }

    @GetMapping("/files/{fileId}/manifest")
    public ResponseEntity<StreamingResponseBody>
    downloadManifest(
            @PathVariable Long fileId
    ) throws Exception {

        return download(
                fileId,
                LockboxObjectStorage.ArtifactType.MANIFEST
        );
    }

    @GetMapping("/files/{fileId}/signature")
    public ResponseEntity<StreamingResponseBody>
    downloadSignature(
            @PathVariable Long fileId
    ) throws Exception {

        return download(
                fileId,
                LockboxObjectStorage.ArtifactType.SIGNATURE
        );
    }
    private ResponseEntity<StreamingResponseBody> download(Long fileId, kakha.kudava.filedrivespring.services.lockbox.LockboxObjectStorage.ArtifactType type) throws Exception {
        LockboxDownloadResult result =
                lockboxService.openDownload(fileId,type);

        return downloadResponse(result);
    }
    private ResponseEntity<StreamingResponseBody> download(Long fileId,long revision,LockboxObjectStorage.ArtifactType type) throws Exception {
        LockboxDownloadResult result=lockboxService.openRevisionDownload(fileId,revision,type);
        return downloadResponse(result);
    }
    static ResponseEntity<StreamingResponseBody> downloadResponse(LockboxDownloadResult result){
        StreamingResponseBody body=output->{
            try(InputStream input=result.inputStream()){
                byte[] buffer=new byte[STREAM_BUFFER_SIZE];int read;
                while((read=input.read(buffer))!=-1){output.write(buffer,0,read);}
                output.flush();
            }
        };
        ContentDisposition disposition=ContentDisposition.attachment().filename(result.fileName()).build();
        return ResponseEntity.ok().contentType(MediaType.parseMediaType(result.contentType()))
                .contentLength(result.size()).cacheControl(CacheControl.noStore())
                .header(HttpHeaders.CONTENT_DISPOSITION,disposition.toString()).body(body);
    }

    @GetMapping(
            value = "/files/private-metadata",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<LockboxPrivateMetadataListResponse>
    privateMetadataList() throws Exception {

        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(
                        lockboxService.privateMetadataList()
                );
    }

    @DeleteMapping("/files/{fileId}")
    public ResponseEntity<Void> delete(@PathVariable Long fileId) throws Exception {
        lockboxService.deleteLockboxFile(fileId);
        return ResponseEntity.noContent().build();
    }
}
