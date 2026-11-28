package com.vulnfollowup.controller;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.vulnfollowup.service.CatalogLoadService;
import com.vulnfollowup.service.VulnerabilityImportService;

/**
 * Carga de datos desde ficheros JSON (multipart/form-data).
 * Los servicios trabajan con rutas de fichero, así que se guarda la subida en un temporal.
 * Si un registro falla, el servicio deshace toda la importación (rollback) y se devuelve 400.
 */
@RestController
public class ImportController {

    private final VulnerabilityImportService vulnerabilityImport;
    private final CatalogLoadService catalogLoad;

    public ImportController(VulnerabilityImportService vulnerabilityImport, CatalogLoadService catalogLoad) {
        this.vulnerabilityImport = vulnerabilityImport;
        this.catalogLoad = catalogLoad;
    }

    @PostMapping("/api/vulnerabilities/import")
    @PreAuthorize("hasAnyRole('ADMIN', 'ANALYST')")
    public Map<String, Integer> importVulnerabilities(@RequestParam("file") MultipartFile file,
                                                      Authentication auth) throws IOException {
        Path temp = toTempFile(file);
        try {
            int imported = vulnerabilityImport.importFile(temp, auth.getName());
            return Map.of("imported", imported);
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    // Proveedores y activos van juntos porque los activos pueden referenciar a un proveedor
    @PostMapping("/api/catalog/import")
    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, String> importCatalog(@RequestParam("providers") MultipartFile providers,
                                             @RequestParam("assets") MultipartFile assets) throws IOException {
        Path providersTemp = toTempFile(providers);
        Path assetsTemp = toTempFile(assets);
        try {
            catalogLoad.load(providersTemp, assetsTemp);
            return Map.of("result", "Catálogo cargado");
        } finally {
            Files.deleteIfExists(providersTemp);
            Files.deleteIfExists(assetsTemp);
        }
    }

    private static Path toTempFile(MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("El fichero " + file.getName() + " está vacío");
        }
        Path temp = Files.createTempFile("import-", ".json");
        file.transferTo(temp);
        return temp;
    }

}
