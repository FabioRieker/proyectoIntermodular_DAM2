package com.vulnfollowup.controller;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vulnfollowup.dto.LoginRequest;
import com.vulnfollowup.dto.LoginResponse;
import com.vulnfollowup.security.JwtService;
import com.vulnfollowup.security.SecurityErrorResponse;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private static final String ROLE_PREFIX = "ROLE_";

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(request.email(), request.password()));

        String role = authentication.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .filter(a -> a.startsWith(ROLE_PREFIX))
            .map(a -> a.substring(ROLE_PREFIX.length()))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("Usuario sin rol asignado"));

        String token = jwtService.generateToken(authentication.getName(), role);
        return new LoginResponse(token, role, jwtService.getExpirationSeconds());
    }

    /**
     * Credenciales incorrectas o usuario inexistente: 401 con el mismo formato que el EntryPoint.
     * Mensaje genérico para no revelar si el email existe.
     */
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> handleAuthenticationException(HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
            .body(SecurityErrorResponse.body(HttpStatus.UNAUTHORIZED, "Credenciales inválidas",
                request.getRequestURI()));
    }

}
