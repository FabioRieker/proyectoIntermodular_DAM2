package com.vulnfollowup;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;

@SpringBootTest
@AutoConfigureMockMvc
class CatalogControllerTest {

    private final String suffix = UUID.randomUUID().toString().substring(0, 8);
    private final String providerCode = "TEST-PRV-" + suffix;
    private final String assetCode = "TEST-ACT-" + suffix;

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void createTestData() {
        jdbc.update("""
            INSERT INTO providers (code, name, service, criticality, contract_ref, review_date, contact)
            VALUES (?, 'Proveedor de prueba', 'Hosting', 'ALTA', 'C-1', DATE '2027-01-31', 'soporte@prueba.example')
            """, providerCode);
        jdbc.update("""
            INSERT INTO assets (code, name, type, owner_id, environment, provider_id)
            SELECT ?, 'API de prueba', 'API', u.id, 'PRUEBAS', p.id
            FROM users u, providers p WHERE u.email = 'analyst@vulnfollowup.local' AND p.code = ?
            """, assetCode, providerCode);
    }

    @AfterEach
    void deleteTestData() {
        jdbc.update("DELETE FROM assets WHERE code = ?", assetCode);
        jdbc.update("DELETE FROM providers WHERE code = ?", providerCode);
    }

    @Test
    void sinTokenDevuelve401() throws Exception {
        mockMvc.perform(get("/api/assets")).andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/providers")).andExpect(status().isUnauthorized());
    }

    @Test
    void viewerVeLosActivosConPropietarioYProveedor() throws Exception {
        mockMvc.perform(get("/api/assets").header(HttpHeaders.AUTHORIZATION, viewerToken()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[?(@.code == '%s')].name", assetCode).value("API de prueba"))
            .andExpect(jsonPath("$[?(@.code == '%s')].active", assetCode).value(true))
            .andExpect(jsonPath("$[?(@.code == '%s')].ownerEmail", assetCode).value("analyst@vulnfollowup.local"))
            .andExpect(jsonPath("$[?(@.code == '%s')].providerCode", assetCode).value(providerCode));
    }

    @Test
    void viewerVeLosProveedores() throws Exception {
        mockMvc.perform(get("/api/providers").header(HttpHeaders.AUTHORIZATION, viewerToken()))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$[?(@.code == '%s')].criticality", providerCode).value("ALTA"))
            .andExpect(jsonPath("$[?(@.code == '%s')].reviewDate", providerCode).value("2027-01-31"));
    }

    private String viewerToken() throws Exception {
        String response = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"viewer@vulnfollowup.local\",\"password\":\"ViewerSec2026!\"}"))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        return "Bearer " + JsonPath.read(response, "$.token");
    }

}
