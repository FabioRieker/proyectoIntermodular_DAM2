package com.vulnfollowup.security;

import java.util.Map;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

// TODO: credenciales de desarrollo hardcodeadas; migrar a UserDetailsService con JPA cuando exista la tabla users.
@Service
public class InMemoryUserDetailsService implements UserDetailsService {

    private final Map<String, UserDetails> users;

    public InMemoryUserDetailsService(PasswordEncoder passwordEncoder) {
        this.users = Map.of(
            "admin@vulnfollowup.local", user("admin@vulnfollowup.local", passwordEncoder.encode("AdminSec2026!"), "ADMIN"),
            "analyst@vulnfollowup.local", user("analyst@vulnfollowup.local", passwordEncoder.encode("AnalystSec2026!"), "ANALYST"),
            "viewer@vulnfollowup.local", user("viewer@vulnfollowup.local", passwordEncoder.encode("ViewerSec2026!"), "VIEWER"));
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDetails user = users.get(username);
        if (user == null) {
            throw new UsernameNotFoundException("Usuario no encontrado");
        }
        // Copia: ProviderManager borra las credenciales del principal tras autenticar.
        return User.withUserDetails(user).build();
    }

    private static UserDetails user(String email, String encodedPassword, String role) {
        // roles("X") genera la authority ROLE_X
        return User.withUsername(email).password(encodedPassword).roles(role).build();
    }

}
