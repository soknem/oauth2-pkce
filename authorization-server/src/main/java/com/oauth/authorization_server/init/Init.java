package com.oauth.authorization_server.init;

import com.oauth.authorization_server.domain.Role;
import com.oauth.authorization_server.domain.User;
import com.oauth.authorization_server.repository.RoleRepository;
import com.oauth.authorization_server.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Component
public class Init {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @PostConstruct
    private void init() {
        try {
            initRoles();
            initUser();
        } catch (Exception e) {
            // Log detailed error information
            System.err.println("Initialization failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void initRoles() {
        try {
            List<String> roleNames = Arrays.asList("USER", "ADMIN", "MODERATOR");

            for (String roleName : roleNames) {

                String roleFullName = "ROLE_" + roleName;
                if (roleRepository.findByName(roleFullName) == null) {
                    Role role = new Role();
                    role.setName(roleFullName);
                    roleRepository.save(role);
                    System.out.println("Initialized role: " + roleFullName);
                }
            }
        } catch (Exception e) {
            System.err.println("Error initializing roles: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public void initUser() {
        try {
            if (userRepository.count() == 0) {
                // Ensure correct role name with "ROLE_" prefix
                Role role = roleRepository.findByName("ROLE_USER");
                if (role == null) {
                    role = new Role();
                    role.setName("ROLE_USER");
                    role = roleRepository.save(role);
                }

                User user = new User();
                user.setEmail("soknem@gmail.com");
                user.setPassword(new BCryptPasswordEncoder().encode("soknem"));
                user.setName("soknem");
                user.setIsEnabled(true);
                user.setRoles(Collections.singletonList(role));

                userRepository.save(user);
                System.out.println("Initialized a new user: " + user.getEmail());
            }
        } catch (Exception e) {
            System.err.println("Error initializing user: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
