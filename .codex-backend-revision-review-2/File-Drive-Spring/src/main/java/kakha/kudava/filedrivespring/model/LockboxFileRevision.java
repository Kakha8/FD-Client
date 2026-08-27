package kakha.kudava.filedrivespring.model;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Entity @Getter @NoArgsConstructor(access=AccessLevel.PROTECTED)
@Table(name="lockbox_file_revisions",uniqueConstraints={@UniqueConstraint(name="uk_lockbox_revision_number",columnNames={"lockbox_file_id","revision"}),@UniqueConstraint(name="uk_lockbox_revision_container_key",columnNames="container_object_key"),@UniqueConstraint(name="uk_lockbox_revision_manifest_key",columnNames="manifest_object_key"),@UniqueConstraint(name="uk_lockbox_revision_signature_key",columnNames="signature_object_key")},indexes=@Index(name="idx_lockbox_revision_file_created",columnList="lockbox_file_id, created_at"))
public class LockboxFileRevision {
 @Id @GeneratedValue(strategy=GenerationType.IDENTITY) private Long id;
 @ManyToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="lockbox_file_id",nullable=false,updatable=false) private LockboxFile lockboxFile;
 @Column(nullable=false,updatable=false) private long revision;
 @Column(name="format_version",nullable=false,updatable=false) private int formatVersion;
 @Column(name="suite_id",nullable=false,updatable=false) private int suiteId;
 @Column(name="container_size",nullable=false,updatable=false) private long containerSize;
 @Column(name="container_hash",nullable=false,updatable=false,length=64) private byte[] containerHash;
 @Column(name="encryption_key_id",nullable=false,updatable=false,length=32) private byte[] encryptionKeyId;
 @Column(name="signing_key_id",nullable=false,updatable=false,length=32) private byte[] signingKeyId;
 @Column(name="device_uuid",nullable=false,updatable=false) private UUID deviceUuid;
 @Column(name="chunk_size",nullable=false,updatable=false) private int chunkSize;
 @Column(name="chunk_count",nullable=false,updatable=false) private long chunkCount;
 @Column(name="container_object_key",nullable=false,updatable=false,length=500) private String containerObjectKey;
 @Column(name="manifest_object_key",nullable=false,updatable=false,length=500) private String manifestObjectKey;
 @Column(name="signature_object_key",nullable=false,updatable=false,length=500) private String signatureObjectKey;
 @Column(name="created_at",nullable=false,updatable=false) private Instant createdAt;
 public LockboxFileRevision(LockboxFile file,long revision,int formatVersion,int suiteId,long containerSize,byte[] containerHash,byte[] encryptionKeyId,byte[] signingKeyId,UUID deviceUuid,int chunkSize,long chunkCount,String containerObjectKey,String manifestObjectKey,String signatureObjectKey){this.lockboxFile=Objects.requireNonNull(file);this.revision=revision;this.formatVersion=formatVersion;this.suiteId=suiteId;this.containerSize=containerSize;this.containerHash=bytes(containerHash,64);this.encryptionKeyId=bytes(encryptionKeyId,32);this.signingKeyId=bytes(signingKeyId,32);this.deviceUuid=Objects.requireNonNull(deviceUuid);this.chunkSize=chunkSize;this.chunkCount=chunkCount;this.containerObjectKey=text(containerObjectKey);this.manifestObjectKey=text(manifestObjectKey);this.signatureObjectKey=text(signatureObjectKey);validate();}
 public byte[] getContainerHash(){return containerHash.clone();} public byte[] getEncryptionKeyId(){return encryptionKeyId.clone();} public byte[] getSigningKeyId(){return signingKeyId.clone();}
 @PrePersist void create(){validate();if(createdAt==null)createdAt=Instant.now();}
 private void validate(){if(revision<1||formatVersion!=3||suiteId!=1||containerSize<0||chunkSize<1||chunkCount<1)throw new IllegalArgumentException("Invalid Lockbox revision metadata");bytes(containerHash,64);bytes(encryptionKeyId,32);bytes(signingKeyId,32);}
 private static byte[] bytes(byte[] v,int n){if(v==null||v.length!=n)throw new IllegalArgumentException("Invalid binary field");return v.clone();} private static String text(String v){if(v==null||v.isBlank())throw new IllegalArgumentException("Object key is required");return v;}
}
