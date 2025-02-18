package dev.criscocodes.spring_security_demo.repository;

import dev.criscocodes.spring_security_demo.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

}
