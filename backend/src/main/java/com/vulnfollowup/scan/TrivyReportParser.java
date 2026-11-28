package com.vulnfollowup.scan;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Lee el JSON de "trivy fs --format json".
 */
public class TrivyReportParser {

    private static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN");

    private final JsonMapper json = JsonMapper.builder().build();

    public List<Finding> parse(String report) {
        JsonNode root;
        try {
            root = json.readTree(report);
        } catch (JacksonException e) {
            throw new IllegalArgumentException("La salida del escáner no es un JSON válido");
        }

        List<Finding> findings = new ArrayList<>();
        // Si no hay hallazgos, Trivy no incluye "Results" o pone "Vulnerabilities": null
        for (JsonNode result : root.path("Results")) {
            for (JsonNode vulnerability : result.path("Vulnerabilities")) {
                String severity = vulnerability.path("Severity").asString("UNKNOWN");
                if (!SEVERITIES.contains(severity)) {
                    severity = "UNKNOWN";
                }
                findings.add(new Finding(
                    vulnerability.path("VulnerabilityID").asString(""),
                    vulnerability.path("PkgName").asString(""),
                    vulnerability.path("InstalledVersion").asString(""),
                    vulnerability.path("FixedVersion").asString(null),
                    severity,
                    null));
            }
        }
        return findings;
    }

    public Map<String, Integer> countBySeverity(List<Finding> findings) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        for (String severity : SEVERITIES) {
            counts.put(severity, 0);
        }
        for (Finding finding : findings) {
            counts.put(finding.severity(), counts.get(finding.severity()) + 1);
        }
        return counts;
    }

}
