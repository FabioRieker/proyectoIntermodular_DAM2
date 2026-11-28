package com.vulnfollowup.controller;

import java.util.Map;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.orm.ObjectOptimisticLockingFailureException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.vulnfollowup.security.SecurityErrorResponse;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Convierte las excepciones de los servicios en respuestas JSON con el mismo formato
 * que los errores 401/403: {"status", "error", "message", "path"}.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    // Los servicios lanzan IllegalArgumentException cuando los datos no son válidos
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> badRequest(IllegalArgumentException e, HttpServletRequest request) {
        return error(HttpStatus.BAD_REQUEST, e.getMessage(), request);
    }

    // Fallos de @Valid en el cuerpo de la petición
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> invalidBody(MethodArgumentNotValidException e,
                                                           HttpServletRequest request) {
        String message = e.getBindingResult().getFieldErrors().stream()
            .map(field -> field.getField() + ": " + field.getDefaultMessage())
            .sorted()
            .reduce((a, b) -> a + "; " + b)
            .orElse("Datos no válidos");
        return error(HttpStatus.BAD_REQUEST, message, request);
    }

    // Por ejemplo, dar de alta un identificador que ya existe (restricción UNIQUE)
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, Object>> conflict(HttpServletRequest request) {
        return error(HttpStatus.CONFLICT, "El registro ya existe o entra en conflicto con otro", request);
    }

    // Dos usuarios modificando la misma vulnerabilidad a la vez (@Version en la entidad)
    @ExceptionHandler(ObjectOptimisticLockingFailureException.class)
    public ResponseEntity<Map<String, Object>> concurrentModification(HttpServletRequest request) {
        return error(HttpStatus.CONFLICT, "Otro usuario ha modificado el registro, vuelve a cargarlo", request);
    }

    private static ResponseEntity<Map<String, Object>> error(HttpStatus status, String message,
                                                             HttpServletRequest request) {
        return ResponseEntity.status(status)
            .body(SecurityErrorResponse.body(status, message, request.getRequestURI()));
    }

}
