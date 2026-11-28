package com.vulnfollowup.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class TrivyReportParserTest {

    private final TrivyReportParser parser = new TrivyReportParser();

    @Test
    void leeLosDatosDeCadaHallazgo() {
        String report = """
            {"Results": [{"Target": "package-lock.json", "Vulnerabilities": [
              {"VulnerabilityID": "CVE-2020-8203", "PkgName": "lodash", "InstalledVersion": "4.17.15",
               "FixedVersion": "4.17.19", "Severity": "HIGH"}
            ]}]}
            """;

        List<Finding> findings = parser.parse(report);

        assertEquals(1, findings.size());
        Finding finding = findings.get(0);
        assertEquals("CVE-2020-8203", finding.id());
        assertEquals("lodash", finding.packageName());
        assertEquals("4.17.15", finding.installedVersion());
        assertEquals("4.17.19", finding.fixedVersion());
        assertEquals("HIGH", finding.severity());
        assertNull(finding.nvd());
    }

    @Test
    void cuentaVulnerabilidadesPorSeveridad() {
        String report = """
            {"Results": [
              {"Target": "a", "Vulnerabilities": [{"Severity": "CRITICAL"}, {"Severity": "HIGH"}, {"Severity": "HIGH"}]},
              {"Target": "b", "Vulnerabilities": null}
            ]}
            """;

        Map<String, Integer> counts = parser.countBySeverity(parser.parse(report));

        assertEquals(1, counts.get("CRITICAL"));
        assertEquals(2, counts.get("HIGH"));
        assertEquals(0, counts.get("LOW"));
    }

    @Test
    void informeSinResultadosNoTieneHallazgos() {
        assertTrue(parser.parse("{\"SchemaVersion\": 2}").isEmpty());
    }

    @Test
    void salidaQueNoEsJsonDaError() {
        assertThrows(IllegalArgumentException.class, () -> parser.parse("FATAL error"));
    }

}
