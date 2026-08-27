package kakha.kudava.filedrivespring.model;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

@Entity @Getter @NoArgsConstructor(access = AccessLevel.PROTECTED)
@Table(name="lockbox_files", uniqueConstraints=@UniqueConstraint(name="uk_lockbox_profile_client_file",columnNames={"profile_id","client_file_id"}), indexes=@Index(name="idx_lockbox_files_created_at",columnList="created_at"))
public class LockboxFile {
 @Id @Column(name="file_id") private Long id;
 @OneToOne(fetch=FetchType.LAZY,optional=false) @MapsId @JoinColumn(name="file_id",nullable=false,unique=true) private FileMetaData file;
 @ManyToOne(fetch=FetchType.LAZY,optional=false) @JoinColumn(name="profile_id",nullable=false,updatable=false) private LockboxProfile profile;
 @Column(name="client_file_id",nullable=false,updatable=false) private UUID clientFileId;
 @Column(name="current_revision",nullable=false) private long currentRevision;
 @Version private long entityVersion;
 @Column(name="created_at",nullable=false,updatable=false) private Instant createdAt;
 @Column(name="updated_at",nullable=false) private Instant updatedAt;
 public LockboxFile(FileMetaData file,LockboxProfile profile,UUID clientFileId,long currentRevision){this.file=Objects.requireNonNull(file);this.profile=Objects.requireNonNull(profile);this.clientFileId=Objects.requireNonNull(clientFileId);if(currentRevision<1)throw new IllegalArgumentException("Current revision must be positive");this.currentRevision=currentRevision;}
 public void advanceToRevision(long expected,long next){if(currentRevision!=expected)throw new IllegalStateException("Revision conflict");if(next!=expected+1)throw new IllegalArgumentException("Revision must increase by one");currentRevision=next;}
 @PrePersist void create(){validate();Instant now=Instant.now();if(createdAt==null)createdAt=now;updatedAt=now;}
 @PreUpdate void update(){validate();updatedAt=Instant.now();}
 private void validate(){if(currentRevision<1)throw new IllegalArgumentException("Current revision must be positive");}
}
