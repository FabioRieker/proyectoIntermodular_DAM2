package com.vulnfollowup.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;

import org.junit.jupiter.api.Test;

class TrivyReportParserTest {

    private final TrivyReportParser parser = new TrivyReportParser();

    @Test
    void cuentaVulnerabilidadesPorSeveridad() {
        String report = """
            {"Results": [
              {"Target": "a", "Vulnerabilities": [{"Severity": "CRITICAL"}, {"Severity": "HIGH"}, {"Severity": "HIGH"}]},
              {"Target": "b", "Vulnerabilities": null}
            ]}
            """;

        Map<String, Integer> counts = parser.countBySeverity(report);

        assertEquals(1, counts.get("CRITICAL"));
        assertEquals(2, counts.get("HIGH"));
        assertEquals(0, counts.get("LOW"));
    }

    @Test
    void salidaQueNoEsJsonDaError() {
        assertThrows(IllegalArgumentException.class, () -> parser.countBySeverity("FATAL error"));
    }

}
