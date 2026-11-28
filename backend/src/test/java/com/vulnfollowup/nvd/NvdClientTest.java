package com.vulnfollowup.nvd;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpServer;

// Servidor HTTP local que hace de NVD, para no depender de internet en los tests.
class NvdClientTest {

    private static final String EMPTY = """
        {"resultsPerPage":0,"startIndex":0,"totalResults":0,"vulnerabilities":[]}
        """;

    private HttpServer server;
    private NvdClient client;
    private final AtomicInteger requests = new AtomicInteger();
    private final AtomicReference<String> lastQuery = new AtomicReference<>();
    private final AtomicReference<String> lastApiKey = new AtomicReference<>();
    private volatile int responseCode = 200;

    @BeforeEach
    void setUp() throws IOException {
        String sample = Files.readString(Path.of("src/test/resources/nvd/CVE-2021-23337.json"));
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/rest/json/cves/2.0", exchange -> {
            requests.incrementAndGet();
            String query = exchange.getRequestURI().getQuery();
            lastQuery.set(query);
            lastApiKey.set(exchange.getRequestHeaders().getFirst("apiKey"));
            String body = query.equals("cveId=CVE-2021-23337") ? sample : EMPTY;
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(responseCode, bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
        client = newClient("");
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    void leeLosDatosDelCve() throws Exception {
        NvdCve cve = client.findCve("CVE-2021-23337");

        assertEquals("CVE-2021-23337", cve.id());
        assertTrue(cve.description().startsWith("Las versiones de Lodash"), "Se prefiere la descripción en español");
        assertEquals("3.1", cve.cvssVersion());
        assertEquals("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", cve.cvssVector());
        assertEquals(7.2, cve.cvssScore());
        assertEquals("HIGH", cve.cvssSeverity());
        assertFalse(cve.references().isEmpty());
        assertEquals("cveId=CVE-2021-23337", lastQuery.get());
    }

    @Test
    void cveQueNoExisteDevuelveNull() throws Exception {
        assertNull(client.findCve("CVE-1999-0000000"));
    }

    @Test
    void laSegundaConsultaSaleDeLaCache() throws Exception {
        client.findCve("CVE-2021-23337");
        client.findCve("CVE-2021-23337");

        assertEquals(1, requests.get());
    }

    @Test
    void errorDeLaNvdLanzaExcepcion() {
        responseCode = 503;

        IOException e = assertThrows(IOException.class, () -> client.findCve("CVE-2021-23337"));
        assertTrue(e.getMessage().contains("503"));
    }

    @Test
    void identificadorNoValidoNoHacePeticion() {
        assertThrows(IllegalArgumentException.class, () -> client.findCve("CVE-2021-1&resultsPerPage=2000"));
        assertThrows(IllegalArgumentException.class, () -> client.findCve("GHSA-xxxx-yyyy-zzzz"));
        assertEquals(0, requests.get());
    }

    @Test
    void conApiKeySeEnviaEnLaCabecera() throws Exception {
        newClient("clave-de-prueba").findCve("CVE-2021-23337");

        assertEquals("clave-de-prueba", lastApiKey.get());
    }

    private NvdClient newClient(String apiKey) {
        String url = "http://localhost:" + server.getAddress().getPort() + "/rest/json/cves/2.0";
        return new NvdClient(url, apiKey, new NvdRateLimiter(100, 1000));
    }

}
