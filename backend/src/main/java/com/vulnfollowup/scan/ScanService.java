package com.vulnfollowup.scan;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.vulnfollowup.nvd.NvdClient;

import jakarta.annotation.PreDestroy;

/**
 * Lanza los análisis de dependencias en segundo plano para no bloquear la petición HTTP.
 */
@Service
public class ScanService {

    private static final Logger log = LoggerFactory.getLogger(ScanService.class);

    private final TrivyRunner runner;
    private final TrivyReportParser parser = new TrivyReportParser();
    private final NvdClient nvdClient;
    private final int maxNvdLookups;

    // Un solo hilo: los análisis no se ejecutan en paralelo sobre el mismo directorio.
    private final ExecutorService executor = Executors.newSingleThreadExecutor();

    // Varias peticiones pueden llegar a la vez, por eso se usan clases thread-safe.
    private final Map<UUID, ScanJob> jobs = new ConcurrentHashMap<>();
    private final AtomicBoolean scanRunning = new AtomicBoolean(false);

    public ScanService(@Value("${scanner.command}") List<String> command,
                       @Value("${scanner.target}") String target,
                       @Value("${scanner.timeout-seconds}") long timeoutSeconds,
                       NvdClient nvdClient,
                       @Value("${nvd.max-lookups}") int maxNvdLookups) {
        this.runner = new TrivyRunner(command, target, timeoutSeconds);
        this.nvdClient = nvdClient;
        this.maxNvdLookups = maxNvdLookups;
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
            List<Finding> findings = addNvdData(parser.parse(report));
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

    /**
     * Completa cada hallazgo con los datos oficiales de la NVD (descripción, CVSS, referencias).
     * Si la NVD falla, el hallazgo se queda sin esos datos pero el análisis sigue.
     * Hay un máximo de consultas por análisis porque sin API key la NVD solo deja 5 cada 30 s.
     */
    private List<Finding> addNvdData(List<Finding> findings) throws InterruptedException {
        List<Finding> result = new ArrayList<>();
        int lookups = 0;
        for (Finding finding : findings) {
            // Trivy también devuelve avisos que no son CVE (GHSA-..., NSWG-...), la NVD no los tiene
            if (lookups < maxNvdLookups && NvdClient.isCveId(finding.id())) {
                lookups++;
                try {
                    finding = finding.withNvd(nvdClient.findCve(finding.id()));
                } catch (IOException e) {
                    log.warn("No se pudo consultar {} en la NVD: {}", finding.id(), e.getMessage());
                }
            }
            result.add(finding);
        }
        return result;
    }

    @PreDestroy
    public void shutdown() {
        executor.shutdownNow();
    }

}
