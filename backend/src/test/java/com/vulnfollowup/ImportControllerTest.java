package com.vulnfollowup;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;

@SpringBootTest
@AutoConfigureMockMvc
class ImportControllerTest {

    private final String suffix = UUID.randomUUID().toString().substring(0, 8);
    private final String providerCode = "TEST-PRV-" + suffix;
    private final String assetCode = "TEST-ACT-" + suffix;

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private JdbcTemplate jdbc;

    @AfterEach
    void deleteTestData() {
        TestData.deleteVulnerabilities(jdbc, "TEST-IMP-" + suffix + "%");
        jdbc.update("DELETE FROM assets WHERE code = ?", assetCode);
        jdbc.update("DELETE FROM providers WHERE code = ?", providerCode);
    }

    @Test
    void adminCargaElCatalogoYAnalystImportaVulnerabilidades() throws Exception {
        mockMvc.perform(multipart("/api/catalog/import")
                .file(json("providers", providersJson()))
                .file(json("assets", assetsJson()))
                .header(HttpHeaders.AUTHORIZATION, bearer("admin@vulnfollowup.local", "AdminSec2026!")))
            .andExpect(status().isOk());

        mockMvc.perform(multipart("/api/vulnerabilities/import")
                .file(json("file", vulnerabilitiesJson("9.8")))
                .header(HttpHeaders.AUTHORIZATION, bearer("analyst@vulnfollowup.local", "AnalystSec2026!")))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.imported").value(2));

        assertEquals(2, countImported());
    }

    @Test
    void siUnRegistroFallaNoSeImportaNinguno() throws Exception {
        loadCatalog();

        // La 2ª fila tiene una nota que no corresponde al vector: falla y se deshace también la 1ª
        mockMvc.perform(multipart("/api/vulnerabilities/import")
                .file(json("file", vulnerabilitiesJson("1.0")))
                .header(HttpHeaders.AUTHORIZATION, bearer("analyst@vulnfollowup.local", "AnalystSec2026!")))
            .andExpect(status().isBadRequest())
            .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.containsString("registro 2")));

        assertEquals(0, countImported());
    }

    @Test
    void analystNoPuedeCargarElCatalogo() throws Exception {
        mockMvc.perform(multipart("/api/catalog/import")
                .file(json("providers", providersJson()))
                .file(json("assets", assetsJson()))
                .header(HttpHeaders.AUTHORIZATION, bearer("analyst@vulnfollowup.local", "AnalystSec2026!")))
            .andExpect(status().isForbidden());
    }

    @Test
    void viewerNoPuedeImportarVulnerabilidades() throws Exception {
        mockMvc.perform(multipart("/api/vulnerabilities/import")
                .file(json("file", "[]"))
                .header(HttpHeaders.AUTHORIZATION, bearer("viewer@vulnfollowup.local", "ViewerSec2026!")))
            .andExpect(status().isForbidden());
    }

    private void loadCatalog() throws Exception {
        mockMvc.perform(multipart("/api/catalog/import")
                .file(json("providers", providersJson()))
                .file(json("assets", assetsJson()))
                .header(HttpHeaders.AUTHORIZATION, bearer("admin@vulnfollowup.local", "AdminSec2026!")))
            .andExpect(status().isOk());
    }

    private int countImported() {
        return jdbc.queryForObject("SELECT count(*) FROM vulnerabilities WHERE identifier LIKE ?",
            Integer.class, "TEST-IMP-" + suffix + "%");
    }

    private String providersJson() {
        return """
            [{"code": "%s", "name": "Proveedor de prueba", "service": "Hosting", "criticality": "ALTA",
              "contractRef": "C-1", "reviewDate": "2027-01-31", "contact": "soporte@prueba.example"}]
            """.formatted(providerCode);
    }

    private String assetsJson() {
        return """
            [{"code": "%s", "name": "API de prueba", "type": "API", "ownerEmail": "analyst@vulnfollowup.local",
              "environment": "PRUEBAS", "active": true, "providerCode": "%s"}]
            """.formatted(assetCode, providerCode);
    }

    private String vulnerabilitiesJson(String secondScore) {
        String row = """
            {"identifier": "TEST-IMP-%s-%d", "title": "Caso importado", "description": "Prueba",
             "detectedOn": "2026-11-01", "assetCodes": ["%s"], "status": "ABIERTA",
             "assessment": {"cvssVersion": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "baseScore": %s}}
            """;
        return "[" + row.formatted(suffix, 1, assetCode, "9.8") + ","
            + row.formatted(suffix, 2, assetCode, secondScore) + "]";
    }

    private static MockMultipartFile json(String name, String content) {
        return new MockMultipartFile(name, name + ".json", MediaType.APPLICATION_JSON_VALUE,
            content.getBytes(StandardCharsets.UTF_8));
    }

    private String bearer(String email, String password) throws Exception {
        String response = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        return "Bearer " + JsonPath.read(response, "$.token");
    }

}
