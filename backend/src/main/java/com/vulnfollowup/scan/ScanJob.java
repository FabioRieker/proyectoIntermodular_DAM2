package com.vulnfollowup.scan;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/**
 * Un análisis lanzado por un usuario.
 * Lo modifica el hilo del ExecutorService y lo leen los hilos de las peticiones HTTP,
 * por eso los métodos son synchronized.
 */
public class ScanJob {

    private final UUID id = UUID.randomUUID();
    private final String requestedBy;
    private final Instant createdAt = Instant.now();

    private ScanStatus status = ScanStatus.EN_CURSO;
    private Instant finishedAt;
    private Map<String, Integer> findings;
    private String error;

    public ScanJob(String requestedBy) {
        this.requestedBy = requestedBy;
    }

    public synchronized void complete(Map<String, Integer> findings) {
        this.findings = findings;
        this.status = ScanStatus.COMPLETADO;
        this.finishedAt = Instant.now();
    }

    public synchronized void fail(String error) {
        this.error = error;
        this.status = ScanStatus.FALLIDO;
        this.finishedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public String getRequestedBy() {
        return requestedBy;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public synchronized ScanStatus getStatus() {
        return status;
    }

    public synchronized Instant getFinishedAt() {
        return finishedAt;
    }

    public synchronized Map<String, Integer> getFindings() {
        return findings;
    }

    public synchronized String getError() {
        return error;
    }

}
