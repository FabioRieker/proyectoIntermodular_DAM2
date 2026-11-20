package com.vulnfollowup;

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
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;

@SpringBootTest
@AutoConfigureMockMvc
class PingControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void pingSinTokenDevuelve401SinCabeceraBasic() throws Exception {
        mockMvc.perform(get("/api/ping"))
            .andExpect(status().isUnauthorized())
            .andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE))
            .andExpect(jsonPath("$.status").value(401))
            .andExpect(jsonPath("$.error").value("Unauthorized"))
            .andExpect(jsonPath("$.path").value("/api/ping"));
    }

    @Test
    void pingConTokenValidoDevuelveUsuarioYRol() throws Exception {
        String token = login("analyst@vulnfollowup.local", "AnalystSec2026!");
        mockMvc.perform(get("/api/ping").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user").value("analyst@vulnfollowup.local"))
            .andExpect(jsonPath("$.role").value("ANALYST"));
    }

    @Test
    void pingAdminConTokenDeAdminDevuelve200() throws Exception {
        String token = login("admin@vulnfollowup.local", "AdminSec2026!");
        mockMvc.perform(get("/api/ping/admin").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.user").value("admin@vulnfollowup.local"))
            .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    void pingAdminConTokenDeViewerDevuelve403() throws Exception {
        String token = login("viewer@vulnfollowup.local", "ViewerSec2026!");
        mockMvc.perform(get("/api/ping/admin").header(HttpHeaders.AUTHORIZATION, "Bearer " + token))
            .andExpect(status().isForbidden())
            .andExpect(header().doesNotExist(HttpHeaders.WWW_AUTHENTICATE))
            .andExpect(jsonPath("$.status").value(403))
            .andExpect(jsonPath("$.error").value("Forbidden"))
            .andExpect(jsonPath("$.path").value("/api/ping/admin"));
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
