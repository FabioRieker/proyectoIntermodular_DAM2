package com.vulnfollowup;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
    "scanner.command=sh",
    "scanner.target=src/test/resources/scanner/fake-trivy.sh"
})
class ScanControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void sinTokenDevuelve401() throws Exception {
        mockMvc.perform(post("/api/scans")).andExpect(status().isUnauthorized());
    }

    @Test
    void viewerNoPuedeLanzarAnalisis() throws Exception {
        String token = login("viewer@vulnfollowup.local", "ViewerSec2026!");

        mockMvc.perform(post("/api/scans").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
            .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/scans").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
            .andExpect(status().isOk());
    }

    @Test
    void analystLanzaAnalisisYConsultaElResultado() throws Exception {
        String token = login("analyst@vulnfollowup.local", "AnalystSec2026!");

        String body = mockMvc.perform(post("/api/scans").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
            .andExpect(status().isAccepted())
            .andExpect(header().exists(HttpHeaders.LOCATION))
            .andReturn().getResponse().getContentAsString();
        String id = JsonPath.read(body, "$.id");

        String scan = "";
        String status = "EN_CURSO";
        for (int i = 0; i < 100 && status.equals("EN_CURSO"); i++) {
            Thread.sleep(50);
            scan = mockMvc.perform(get("/api/scans/" + id).header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
            status = JsonPath.read(scan, "$.status");
        }

        assertEquals("COMPLETADO", status);
        assertEquals(1, (Integer) JsonPath.read(scan, "$.findings.CRITICAL"));
    }

    private String login(String email, String password) throws Exception {
        String response = mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}"))
            .andExpect(status().isOk())
            .andReturn().getResponse().getContentAsString();
        return JsonPath.read(response, "$.token");
    }

}
