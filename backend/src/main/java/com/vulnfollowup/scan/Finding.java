package com.vulnfollowup.scan;

import com.vulnfollowup.nvd.NvdCve;

/**
 * Una vulnerabilidad encontrada por el escáner en una dependencia.
 * nvd es null si no se han podido consultar los datos oficiales en la NVD.
 */
public record Finding(
        String id,
        String packageName,
        String installedVersion,
        String fixedVersion,
        String severity,
        NvdCve nvd) {

    public Finding withNvd(NvdCve nvd) {
        return new Finding(id, packageName, installedVersion, fixedVersion, severity, nvd);
    }

}
