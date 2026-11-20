package com.vulnfollowup.controller;

import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

// TODO: endpoint de verificación, borrar cuando existan endpoints reales de negocio.
@RestController
public class PingController {

    private static final String ROLE_PREFIX = "ROLE_";

    @GetMapping("/api/ping")
    public Map<String, String> ping(Authentication auth) {
        return userAndRole(auth);
    }

    // endpoint de verificación RBAC; solo ADMIN.
    @GetMapping("/api/ping/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> pingAdmin(Authentication auth) {
        return userAndRole(auth);
    }

    private static Map<String, String> userAndRole(Authentication auth) {
        String role = auth.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .filter(a -> a.startsWith(ROLE_PREFIX))
            .map(a -> a.substring(ROLE_PREFIX.length()))
            .findFirst()
            .orElse("");
        return Map.of("user", auth.getName(), "role", role);
    }

}
