package com.vulnfollowup.service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
class CatalogLoadServiceTest {
    @Autowired
    private CatalogLoadService catalog;
    @Autowired
    private JdbcTemplate jdbc;

    @ParameterizedTest
    @CsvSource(delimiter = '|', textBlock = """
        AST-CAT-2 | analyst@vulnfollowup.local | PRV-CAT-AUSENTE | Proveedor inexistente: PRV-CAT-AUSENTE
        AST-CAT-2 | ausente@vulnfollowup.local | PRV-CAT-NUEVO | Propietario inexistente: ausente@vulnfollowup.local
        AST-CAT-1 | analyst@vulnfollowup.local | PRV-CAT-NUEVO | Código duplicado.
        """)
    void revierteProveedorYPrimerActivoSiFallaElSegundo(String code, String owner, String provider, String detail,
                                                        @TempDir Path directory) throws IOException {
        Path providersFile = Files.writeString(directory.resolve("providers.json"), """
            [
              {"code":"PRV-CAT-NUEVO","name":"Proveedor de prueba","service":"Custodia",
               "criticality":"ALTA","contractRef":"PRUEBA","reviewDate":"2028-06-30","contact":"prueba@example.com"}
            ]
            """);
        Path assetsFile = Files.writeString(directory.resolve("assets.json"), """
            [
              {"code":"AST-CAT-1","name":"Primer activo","type":"API","ownerEmail":"analyst@vulnfollowup.local",
               "environment":"PRUEBAS","active":true,"providerCode":"PRV-CAT-NUEVO"},
              {"code":"%s","name":"Segundo activo","type":"API","ownerEmail":"%s",
               "environment":"PRUEBAS","active":true,"providerCode":"%s"}
            ]
            """.formatted(code, owner, provider));

        var error = assertThrows(IllegalArgumentException.class, () -> catalog.load(providersFile, assetsFile));
        assertEquals(assetsFile + " (" + code + "): " + detail, error.getMessage());
        assertEquals(0, jdbc.queryForObject("""
            SELECT count(*) FROM assets WHERE code IN ('AST-CAT-1', 'AST-CAT-2')
            """, Integer.class));
        assertEquals(0, jdbc.queryForObject("""
            SELECT count(*) FROM providers WHERE code = 'PRV-CAT-NUEVO'
            """, Integer.class));
    }
}
