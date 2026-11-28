package com.vulnfollowup.scan;

import java.util.LinkedHashMap;
import java.util.Map;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Lee el JSON de "trivy fs --format json" y cuenta las vulnerabilidades por severidad.
 */
public class TrivyReportParser {

    private final JsonMapper json = JsonMapper.builder().build();

    public Map<String, Integer> countBySeverity(String report) {
        JsonNode root;
        try {
            root = json.readTree(report);
        } catch (JacksonException e) {
            throw new IllegalArgumentException("La salida del escáner no es un JSON válido");
        }

        Map<String, Integer> counts = new LinkedHashMap<>();
        counts.put("CRITICAL", 0);
        counts.put("HIGH", 0);
        counts.put("MEDIUM", 0);
        counts.put("LOW", 0);
        counts.put("UNKNOWN", 0);

        // Si no hay hallazgos, Trivy no incluye "Results" o pone "Vulnerabilities": null
        for (JsonNode result : root.path("Results")) {
            for (JsonNode vulnerability : result.path("Vulnerabilities")) {
                String severity = vulnerability.path("Severity").asString("UNKNOWN");
                if (!counts.containsKey(severity)) {
                    severity = "UNKNOWN";
                }
                counts.put(severity, counts.get(severity) + 1);
            }
        }
        return counts;
    }

}
