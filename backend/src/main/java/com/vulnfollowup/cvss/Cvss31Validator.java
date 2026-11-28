package com.vulnfollowup.cvss;

import java.math.BigDecimal;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import us.springett.cvss.Cvss;

public final class Cvss31Validator {
    private static final String VERSION = "3.1";
    private static final String PREFIX = "CVSS:" + VERSION;
    private static final Map<String, String> BASE_VALUES = Map.of(
        "AV", "NALP", "AC", "LH", "PR", "NLH", "UI", "NR",
        "S", "UC", "C", "NLH", "I", "NLH", "A", "NLH"
    );

    public void validate(String version, String vector, BigDecimal declaredScore) {
        if (!VERSION.equals(version)) {
            throw new IllegalArgumentException("Versión CVSS no admitida: se esperaba 3.1.");
        }
        if (vector == null || vector.isBlank()) {
            throw new IllegalArgumentException("Se requiere un vector CVSS.");
        }

        String[] segments = vector.split("/", -1);
        if (!PREFIX.equals(segments[0])) {
            throw new IllegalArgumentException("Prefijo del vector incompatible: se esperaba CVSS:3.1.");
        }

        Set<String> seen = new HashSet<>();
        for (int i = 1; i < segments.length; i++) {
            String[] metric = segments[i].split(":", -1);
            if (metric.length != 2) {
                throw new IllegalArgumentException("Segmento inválido en el vector: " + segments[i]);
            }

            String name = metric[0];
            String value = metric[1];
            String allowed = BASE_VALUES.get(name);
            if (allowed == null) {
                throw new IllegalArgumentException("Métrica Base desconocida: " + name);
            }
            if (value.length() != 1 || !allowed.contains(value)) {
                throw new IllegalArgumentException("Valor inválido para la métrica Base " + name + ": " + value);
            }
            if (!seen.add(name)) {
                throw new IllegalArgumentException("Métrica Base repetida: " + name);
            }
        }
        if (seen.size() != BASE_VALUES.size()) {
            throw new IllegalArgumentException("El vector debe incluir las ocho métricas Base de CVSS 3.1.");
        }

        if (declaredScore == null) {
            throw new IllegalArgumentException("Se requiere la nota Base declarada.");
        }
        BigDecimal calculatedScore = BigDecimal.valueOf(Cvss.fromVector(vector).calculateScore().getBaseScore());
        if (declaredScore.compareTo(calculatedScore) != 0) {
            throw new IllegalArgumentException("La nota Base declarada no coincide con el vector. Se esperaba "
                + calculatedScore.toPlainString() + ".");
        }
    }
}
