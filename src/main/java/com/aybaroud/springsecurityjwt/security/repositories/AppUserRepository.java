package com.aybaroud.springsecurityjwt.security.repositories;

import com.aybaroud.springsecurityjwt.security.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository
        extends JpaRepository<AppUser,Long> {
    AppUser findByUsername(String username);
}
