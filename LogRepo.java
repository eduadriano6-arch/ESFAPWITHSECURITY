package pe.edu.esfap.portal;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
public interface LogRepo extends JpaRepository<LogEntry, Long> { List<LogEntry> findTop100ByOrderByIdDesc(); }
