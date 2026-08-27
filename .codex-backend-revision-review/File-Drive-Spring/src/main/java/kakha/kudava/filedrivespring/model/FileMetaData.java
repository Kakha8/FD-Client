package kakha.kudava.filedrivespring.model;

import jakarta.persistence.*;
import kakha.kudava.filedrivespring.enums.DriveSpace;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.time.LocalDateTime;

@Entity
@Getter
@Setter
@Table(name = "files")
public class FileMetaData {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column(nullable = false, unique = true)
    private String objectKey;

    @Column(nullable = false)
    private String fileName;

    @Column(nullable = false)
    private String objectType;

    @Column(nullable = false)
    private String checksum;

    @Column(nullable = false)
    private Instant creationDate = Instant.now();

    @Column
    private Instant lastModifiedDate = Instant.now();

    @Column(nullable = false)
    private Long size;

    @Column(nullable = false)
    private boolean deleted;

    @Column
    private Instant deletedAt;

    @Column(nullable = false)
    private boolean permanentlyDeleted;

    private Instant permanentlyDeletedAt;

    @Column
    private String originalObjectKey;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "owner_id", nullable = false)
    private User owner;

    @ManyToOne(fetch = FetchType.EAGER)
    private Folders parent;

    @Enumerated(EnumType.STRING)
    @Column(
            name = "drive_space",
            nullable = false,
            length = 20
    )
    private DriveSpace driveSpace = DriveSpace.DRIVE;
}
