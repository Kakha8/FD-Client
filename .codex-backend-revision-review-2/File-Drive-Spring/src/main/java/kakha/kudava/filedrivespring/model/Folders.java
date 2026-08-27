package kakha.kudava.filedrivespring.model;

import jakarta.persistence.*;
import kakha.kudava.filedrivespring.enums.DriveSpace;
import kakha.kudava.filedrivespring.enums.FolderSpace;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Setter
@Getter
@Table(name = "folders")
public class Folders {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String prefix;

    @Column(nullable = false)
    private boolean deleted = false;

    @Column
    private Instant deletedAt;

    @Column(nullable = false)
    private boolean permanentlyDeleted = false;

    private Instant permanentlyDeletedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "parent_id")
    private Folders parent;

    @OneToMany(mappedBy = "parent")
    private List<Folders> children;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "owner_id")
    private User owner;

    @Enumerated(EnumType.STRING)
    @Column(
            name = "drive_space",
            nullable = false,
            length = 20
    )
    private DriveSpace driveSpace = DriveSpace.DRIVE;
}
