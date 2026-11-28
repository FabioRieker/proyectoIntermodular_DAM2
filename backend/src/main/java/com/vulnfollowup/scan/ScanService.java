package com.vulnfollowup.scan;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PreDestroy;

/**
 * Lanza los análisis de dependencias en segundo plano para no bloquear la petición HTTP.
 */
@Service
public class ScanService {

    private final TrivyRunner runner;
    private final TrivyReportParser parser = new TrivyReportParser();

    // Un solo hilo: los análisis no se ejecutan en paralelo sobre el mismo directorio.
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    // Varias peticiones pueden llegar a la vez, por eso se usan clases thread-safe.
    private final Map<UUID, ScanJob> jobs = new ConcurrentHashMap<>();
    private final AtomicBoolean scanRunning = new AtomicBoolean(false);

    public ScanService(@Value("${scanner.command}") List<String> command,
                       @Value("${scanner.target}") String target,
                       @Value("${scanner.timeout-seconds}") long timeoutSeconds) {
        this.runner = new TrivyRunner(command, target, timeoutSeconds);
    }

    public ScanJob start(String requestedBy) {
        // compareAndSet comprueba y cambia el valor en un solo paso. Con un if normal,
        // dos peticiones a la vez podrían ver "false" y arrancar las dos.
        if (!scanRunning.compareAndSet(false, true)) {
            throw new ScanAlreadyRunningException();
        }
        ScanJob job = new ScanJob(requestedBy);
        jobs.put(job.getId(), job);
        executor.submit(() -> runScan(job));
        return job;
    }

    public ScanJob find(UUID id) {
        return jobs.get(id);
    }

    public List<ScanJob> findAll() {
        List<ScanJob> list = new ArrayList<>(jobs.values());
        list.sort(Comparator.comparing(ScanJob::getCreatedAt).reversed());
        return list;
    }

    private void runScan(ScanJob job) {
        try {
            String report = runner.run();
            List<Finding> findings = parser.parse(report);
            job.complete(parser.countBySeverity(findings), findings);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            job.fail("Análisis interrumpido");
        } catch (Exception e) {
            job.fail(e.getMessage());
        } finally {
            // Se libera siempre, aunque falle, para poder lanzar otro análisis.
            scanRunning.set(false);
        }
    }

    @PreDestroy
    public void shutdown() {
        executor.shutdownNow();
    }

}
