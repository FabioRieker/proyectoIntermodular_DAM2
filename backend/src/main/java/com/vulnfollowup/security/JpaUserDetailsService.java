package com.vulnfollowup.security;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.vulnfollowup.model.UserAccount;
import com.vulnfollowup.repository.UserAccountRepository;

/** Carga usuarios desde la tabla users de PostgreSQL. */
@Service
public class JpaUserDetailsService implements UserDetailsService {

    // Mensaje genérico: no revela si el email existe (anti-enumeración).
    private static final String INVALID_CREDENTIALS = "Credenciales inválidas";

    private final UserAccountRepository repository;

    public JpaUserDetailsService(UserAccountRepository repository) {
        this.repository = repository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        if (email == null) {
            throw new UsernameNotFoundException(INVALID_CREDENTIALS);
        }
        UserAccount account = repository.findByEmail(email.toLowerCase().trim())
            .filter(UserAccount::isEnabled)
            .orElseThrow(() -> new UsernameNotFoundException(INVALID_CREDENTIALS));

        return User.builder()
            .username(account.getEmail())
            .password(account.getPasswordHash())
            .authorities(new SimpleGrantedAuthority("ROLE_" + account.getRole()))
            .disabled(!account.isEnabled())
            .build();
    }

}
