package com.aybaroud.springsecurityjwt.security.service;

import com.aybaroud.springsecurityjwt.security.entities.AppRole;
import com.aybaroud.springsecurityjwt.security.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRole addNewRole(AppRole appRole);
    void addRoleToUser(String username, String roleName);
    AppUser loadUserByUserName(String username);
    List<AppUser> getUsers();
    List<AppRole> getRoles();
}
