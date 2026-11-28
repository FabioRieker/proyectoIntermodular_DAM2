package com.vulnfollowup.nvd;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Cliente de la API de vulnerabilidades de la NVD (https://nvd.nist.gov/developers/vulnerabilities).
 */
@Component
public class NvdClient {

    private static final long WINDOW_MILLIS = 30_000;
    private static final int MAX_REFERENCES = 5;

    private final String baseUrl;
    private final String apiKey;
    private final NvdRateLimiter rateLimiter;

    private final HttpClient http = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .build();
    private final JsonMapper json = JsonMapper.builder().build();

    // Los datos de un CVE casi no cambian: se guardan para no repetir peticiones.
    private final Map<String, NvdCve> cache = new ConcurrentHashMap<>();

    @Autowired
    public NvdClient(@Value("${nvd.base-url}") String baseUrl,
                     @Value("${nvd.api-key:}") String apiKey) {
        this(baseUrl, apiKey, new NvdRateLimiter(apiKey.isBlank() ? 5 : 50, WINDOW_MILLIS));
    }

    public NvdClient(String baseUrl, String apiKey, NvdRateLimiter rateLimiter) {
        this.baseUrl = baseUrl;
        this.apiKey = apiKey;
        this.rateLimiter = rateLimiter;
    }

    public static boolean isCveId(String id) {
        return id != null && id.matches("CVE-\\d{4}-\\d{4,}");
    }

    /**
     * Devuelve los datos del CVE o null si la NVD no lo tiene.
     */
    public NvdCve findCve(String cveId) throws IOException, InterruptedException {
        // Se valida el formato antes de meterlo en la URL
        if (!isCveId(cveId)) {
            throw new IllegalArgumentException("Identificador de CVE no válido: " + cveId);
        }
        NvdCve cached = cache.get(cveId);
        if (cached != null) {
            return cached;
        }

        rateLimiter.acquire();

        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(baseUrl + "?cveId=" + cveId))
            .timeout(Duration.ofSeconds(20))
            .GET();
        if (!apiKey.isBlank()) {
            request.header("apiKey", apiKey);
        }
        HttpResponse<String> response = http.send(request.build(), HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("La NVD respondió con código " + response.statusCode());
        }

        NvdCve cve = parse(response.body());
        if (cve != null) {
            cache.put(cveId, cve);
        }
        return cve;
    }

    private NvdCve parse(String body) {
        JsonNode vulnerabilities = json.readTree(body).path("vulnerabilities");
        if (vulnerabilities.isEmpty()) {
            return null;
        }
        JsonNode cve = vulnerabilities.get(0).path("cve");

        // Primero CVSS 3.1 y, si no hay, CVSS 4.0
        JsonNode metrics = cve.path("metrics");
        JsonNode cvss = chooseMetric(metrics.path("cvssMetricV31"));
        if (cvss == null) {
            cvss = chooseMetric(metrics.path("cvssMetricV40"));
        }

        List<String> references = new ArrayList<>();
        for (JsonNode reference : cve.path("references")) {
            if (references.size() == MAX_REFERENCES) {
                break;
            }
            references.add(reference.path("url").asString());
        }

        return new NvdCve(
            cve.path("id").asString(),
            chooseDescription(cve.path("descriptions")),
            cve.path("published").asString(null),
            cvss == null ? null : cvss.path("version").asString(null),
            cvss == null ? null : cvss.path("vectorString").asString(null),
            cvss == null ? null : Double.valueOf(cvss.path("baseScore").asDouble()),
            cvss == null ? null : cvss.path("baseSeverity").asString(null),
            references);
    }

    // Puede haber varias valoraciones del mismo CVE: se prefiere la del NIST ("Primary").
    private static JsonNode chooseMetric(JsonNode metricList) {
        JsonNode first = null;
        for (JsonNode metric : metricList) {
            if (first == null) {
                first = metric;
            }
            if ("Primary".equals(metric.path("type").asString(""))) {
                return metric.path("cvssData");
            }
        }
        return first == null ? null : first.path("cvssData");
    }

    // Descripción en español si existe; si no, en inglés.
    private static String chooseDescription(JsonNode descriptions) {
        String english = null;
        for (JsonNode description : descriptions) {
            String lang = description.path("lang").asString("");
            if (lang.equals("es")) {
                return description.path("value").asString();
            }
            if (lang.equals("en")) {
                english = description.path("value").asString();
            }
        }
        return english;
    }

}
