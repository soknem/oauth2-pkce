package app.authorizedserverjpa.repository;


import app.authorizedserverjpa.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleRepository extends JpaRepository<Role, Integer> {
}
