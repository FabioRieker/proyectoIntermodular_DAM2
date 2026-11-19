package com.vulnfollowup.security;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.json.JsonMapper;

/**
 * Formato común de los errores de seguridad (401/403):
 * {"status":..,"error":"..","message":"..","path":".."}
 */
public final class SecurityErrorResponse {

    private SecurityErrorResponse() {
    }

    public static Map<String, Object> body(HttpStatus status, String message, String path) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("message", message);
        body.put("path", path);
        return body;
    }

    public static void write(JsonMapper jsonMapper, HttpServletRequest request,
                             HttpServletResponse response, HttpStatus status, String message)
            throws IOException {
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        jsonMapper.writeValue(response.getOutputStream(), body(status, message, request.getRequestURI()));
    }

}
