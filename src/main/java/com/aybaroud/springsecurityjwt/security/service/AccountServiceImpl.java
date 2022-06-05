package com.aybaroud.springsecurityjwt.security.service;

import com.aybaroud.springsecurityjwt.security.entities.AppRole;
import com.aybaroud.springsecurityjwt.security.entities.AppUser;
import com.aybaroud.springsecurityjwt.security.repositories.AppRoleRepository;
import com.aybaroud.springsecurityjwt.security.repositories.AppUserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@Transactional
@AllArgsConstructor
public class AccountServiceImpl implements AccountService {

    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;
    private PasswordEncoder passwordEncoder;

    @Override
    public AppUser addNewUser(AppUser appUser) {
        String password = appUser.getPassword();
        appUser.setPassword(passwordEncoder.encode(password));
        return appUserRepository.save(appUser);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    @Override
    public void addRoleToUser(String username, String roleName) {
        AppUser appUser = appUserRepository.findByUsername(username);
        AppRole appRole = appRoleRepository.findByRoleName(roleName);
        appUser.getAppRoles().add(appRole);
    }

    @Override
    public AppUser loadUserByUserName(String username) {
        return appUserRepository.findByUsername(username);
    }

    @Override
    public List<AppUser> getUsers() {
        return appUserRepository.findAll();
    }

    @Override
    public List<AppRole> getRoles() {
        return appRoleRepository.findAll();
    }


}
