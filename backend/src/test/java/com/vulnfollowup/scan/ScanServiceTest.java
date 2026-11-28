package com.vulnfollowup.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ScanServiceTest {

    private static final String FAKE_TRIVY = "src/test/resources/scanner/fake-trivy.sh";

    private ScanService service;

    @AfterEach
    void tearDown() {
        service.shutdown();
    }

    @Test
    void analisisCorrectoTerminaCompletado() throws Exception {
        service = new ScanService(List.of("sh"), FAKE_TRIVY, 10, null, 0);

        ScanJob job = service.start("analyst@test");
        waitUntilFinished(job);

        assertEquals(ScanStatus.COMPLETADO, job.getStatus());
        assertEquals(1, job.getSummary().get("CRITICAL"));
        assertEquals(1, job.getSummary().get("HIGH"));
        assertNotNull(job.getFinishedAt());
    }

    @Test
    void analisisConErrorTerminaFallido() throws Exception {
        service = new ScanService(List.of("sh", "-c", "exit 2"), "x", 10, null, 0);

        ScanJob job = service.start("analyst@test");
        waitUntilFinished(job);

        assertEquals(ScanStatus.FALLIDO, job.getStatus());
        assertNotNull(job.getError());
    }

    @Test
    void noSePuedenLanzarDosAnalisisALaVez() throws Exception {
        // El falso escáner tarda 1 segundo para que el primero siga en curso.
        service = new ScanService(List.of("sh", "-c", "sleep 1; sh " + FAKE_TRIVY), "x", 10, null, 0);

        ScanJob first = service.start("a");
        assertThrows(ScanAlreadyRunningException.class, () -> service.start("b"));

        // Cuando termina el primero ya se puede lanzar otro.
        waitUntilFinished(first);
        ScanJob second = service.start("b");
        waitUntilFinished(second);
        assertEquals(ScanStatus.COMPLETADO, second.getStatus());
    }

    @Test
    void conVariosHilosALaVezSoloSeAceptaUno() throws Exception {
        service = new ScanService(List.of("sh", "-c", "sleep 1; sh " + FAKE_TRIVY), "x", 10, null, 0);
        AtomicInteger accepted = new AtomicInteger();
        AtomicInteger rejected = new AtomicInteger();

        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            Thread t = new Thread(() -> {
                try {
                    service.start("user");
                    accepted.incrementAndGet();
                } catch (ScanAlreadyRunningException e) {
                    rejected.incrementAndGet();
                }
            });
            threads.add(t);
        }
        for (Thread t : threads) {
            t.start();
        }
        for (Thread t : threads) {
            t.join();
        }

        assertEquals(1, accepted.get());
        assertEquals(9, rejected.get());
        assertEquals(1, service.findAll().size());
    }

    private static void waitUntilFinished(ScanJob job) throws InterruptedException {
        for (int i = 0; i < 100 && job.getStatus() == ScanStatus.EN_CURSO; i++) {
            Thread.sleep(50);
        }
    }

}
