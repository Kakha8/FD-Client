package kakha.kudava.filedrivespring.repository;

import kakha.kudava.filedrivespring.model.ActionLogs;
import kakha.kudava.filedrivespring.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Range;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import org.springframework.data.domain.Pageable;
import java.util.Collection;
import java.util.List;

@Repository
public interface ActionLogsRepository
        extends JpaRepository<ActionLogs, Long>,
        JpaSpecificationExecutor<ActionLogs> {

    Page<ActionLogs> findAllByUserOrderByTimestampDesc(
            User user,
            Pageable pageable
    );

    List<ActionLogs> findTop1000ByUserOrderByTimestampDesc(
            User user
    );
}
