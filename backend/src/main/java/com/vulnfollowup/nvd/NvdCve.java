package com.vulnfollowup.nvd;

import java.util.List;

/**
 * Datos oficiales de un CVE según la NVD (NIST).
 * Los campos cvss* son null si la NVD todavía no ha valorado el CVE.
 */
public record NvdCve(
        String id,
        String description,
        String published,
        String cvssVersion,
        String cvssVector,
        Double cvssScore,
        String cvssSeverity,
        List<String> references) {
}
