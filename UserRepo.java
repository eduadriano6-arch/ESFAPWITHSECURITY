package pe.edu.esfap.portal;
import org.springframework.data.jpa.repository.JpaRepository;
public interface UserRepo extends JpaRepository<AppUser, String> {}
