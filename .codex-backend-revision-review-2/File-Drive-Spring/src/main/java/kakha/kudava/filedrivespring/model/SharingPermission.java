package kakha.kudava.filedrivespring.model;

import jakarta.persistence.*;
import kakha.kudava.filedrivespring.enums.SharingRole;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "sharing_permissions")
public class SharingPermission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    private Folders folder;

    @ManyToOne
    private FileMetaData file;

    @ManyToOne
    private User owner;

    @ManyToOne
    private User sharedWith;

    @ManyToOne
    private User sharedBy;

    @Enumerated(EnumType.STRING)
    private SharingRole role;

    private boolean active = true;

    private Instant createdAt;

    private Instant revokedAt;
    private Instant updatedAt;
}