package com.vulnfollowup.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.vulnfollowup.nvd.NvdClient;
import com.vulnfollowup.nvd.NvdCve;
import com.vulnfollowup.nvd.NvdRateLimiter;

class ScanServiceNvdTest {

    // El falso escáner devuelve CVE-2024-0001 (CRITICAL) y CVE-2024-0002 (HIGH)
    private static final String FAKE_TRIVY = "src/test/resources/scanner/fake-trivy.sh";

    private ScanService service;

    @AfterEach
    void tearDown() {
        service.shutdown();
    }

    // NVD falsa: conoce CVE-2024-0001 y falla con CVE-2024-0002
    private static class FakeNvdClient extends NvdClient {
        FakeNvdClient() {
            super("http://no-se-usa", "", new NvdRateLimiter(100, 1000));
        }

        @Override
        public NvdCve findCve(String cveId) throws IOException {
            if (cveId.equals("CVE-2024-0001")) {
                return new NvdCve(cveId, "Descripción oficial", "2024-01-01", "3.1",
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL", List.of());
            }
            throw new IOException("La NVD respondió con código 503");
        }
    }

    @Test
    void losHallazgosSeCompletanConLaNvdYUnFalloNoRompeElAnalisis() throws Exception {
        service = new ScanService(List.of("sh"), FAKE_TRIVY, 10, new FakeNvdClient(), 20);

        ScanJob job = service.start("analyst@test");
        waitUntilFinished(job);

        assertEquals(ScanStatus.COMPLETADO, job.getStatus());
        Finding first = job.getFindings().get(0);
        Finding second = job.getFindings().get(1);
        assertNotNull(first.nvd());
        assertEquals(9.8, first.nvd().cvssScore());
        assertNull(second.nvd(), "Si la NVD falla, el hallazgo queda sin datos oficiales");
    }

    @Test
    void noSeHacenMasConsultasQueElMaximo() throws Exception {
        service = new ScanService(List.of("sh"), FAKE_TRIVY, 10, new FakeNvdClient(), 0);

        ScanJob job = service.start("analyst@test");
        waitUntilFinished(job);

        assertEquals(2, job.getFindings().size());
        assertNull(job.getFindings().get(0).nvd());
    }

    private static void waitUntilFinished(ScanJob job) throws InterruptedException {
        for (int i = 0; i < 100 && job.getStatus() == ScanStatus.EN_CURSO; i++) {
            Thread.sleep(50);
        }
    }

}
