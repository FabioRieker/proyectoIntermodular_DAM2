package com.vulnfollowup;

import org.springframework.jdbc.core.JdbcTemplate;

/** Limpieza de los datos que crean los tests de la API. */
final class TestData {

    private TestData() {
    }

    // Borra las vulnerabilidades cuyo identificador encaja con el patrón LIKE, con sus filas relacionadas
    static void deleteVulnerabilities(JdbcTemplate jdbc, String identifierPattern) {
        String ids = "SELECT id FROM vulnerabilities WHERE identifier LIKE ?";
        jdbc.update("DELETE FROM cvss_assessments WHERE vulnerability_id IN (" + ids + ")", identifierPattern);
        jdbc.update("DELETE FROM vulnerability_assets WHERE vulnerability_id IN (" + ids + ")", identifierPattern);
        jdbc.update("DELETE FROM vulnerabilities WHERE identifier LIKE ?", identifierPattern);
    }

}
