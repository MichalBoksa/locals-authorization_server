package com.projekt.locals.repositories;

import com.projekt.locals.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Integer> {
    Optional<Role> findRoleById(Integer id);

    Optional<Role> findRoleByName(String name);
}
