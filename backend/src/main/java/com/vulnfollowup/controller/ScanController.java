package com.vulnfollowup.controller;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.vulnfollowup.scan.ScanAlreadyRunningException;
import com.vulnfollowup.scan.ScanJob;
import com.vulnfollowup.scan.ScanService;
import com.vulnfollowup.security.SecurityErrorResponse;

import jakarta.servlet.http.HttpServletRequest;

// Lanzar análisis: ADMIN y ANALYST. Consultarlos: cualquier usuario autenticado.
@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final ScanService scanService;

    public ScanController(ScanService scanService) {
        this.scanService = scanService;
    }

    // 202 Accepted: el análisis se ha lanzado pero todavía no ha terminado.
    @PostMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public ResponseEntity<ScanJob> start(Authentication auth) {
        ScanJob job = scanService.start(auth.getName());
        return ResponseEntity.accepted()
            .location(URI.create("/api/scans/" + job.getId()))
            .body(job);
    }

    @GetMapping
    public List<ScanJob> findAll() {
        return scanService.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> find(@PathVariable UUID id, HttpServletRequest request) {
        ScanJob job = scanService.find(id);
        if (job == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(SecurityErrorResponse.body(HttpStatus.NOT_FOUND, "Análisis no encontrado",
                    request.getRequestURI()));
        }
        return ResponseEntity.ok(job);
    }

    @ExceptionHandler(ScanAlreadyRunningException.class)
    public ResponseEntity<Map<String, Object>> alreadyRunning(ScanAlreadyRunningException e,
                                                              HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.CONFLICT)
            .body(SecurityErrorResponse.body(HttpStatus.CONFLICT, e.getMessage(), request.getRequestURI()));
    }

}
