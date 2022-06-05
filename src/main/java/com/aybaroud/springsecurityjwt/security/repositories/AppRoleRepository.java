package com.aybaroud.springsecurityjwt.security.repositories;

import com.aybaroud.springsecurityjwt.security.entities.AppRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository
        extends JpaRepository<AppRole,String> {
    AppRole findByRoleName(String roleName);
}
