package com.vulnfollowup.cvss;

import java.math.BigDecimal;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Cvss31ValidatorTest {
    private static final String VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
    private static final BigDecimal SCORE = new BigDecimal("9.8");

    private final Cvss31Validator validator = new Cvss31Validator();

    @Test
    void aceptaUnaValoracionCorrecta() {
        assertDoesNotThrow(() -> validator.validate("3.1", VECTOR, SCORE));
    }

    @Test
    void rechazaUnValorDeMetricaConCaracteresAdicionales() {
        var error = assertThrows(IllegalArgumentException.class,
            () -> validator.validate("3.1", VECTOR.replace("A:H", "A:Hextra"), SCORE));
        assertTrue(error.getMessage().contains("Valor inválido para la métrica Base A"));
    }

    @Test
    void rechazaUnaNotaValidaQueNoCoincideConElVector() {
        var error = assertThrows(IllegalArgumentException.class,
            () -> validator.validate("3.1", VECTOR, new BigDecimal("9.7")));
        assertTrue(error.getMessage().contains("Se esperaba 9.8"));
    }

    @Test
    void rechazaUnaVersionDeclaradaIncompatible() {
        var error = assertThrows(IllegalArgumentException.class,
            () -> validator.validate("4.0", VECTOR, SCORE));
        assertTrue(error.getMessage().contains("Versión CVSS no admitida"));
    }

    @Test
    void rechazaUnPrefijoIncompatible() {
        var error = assertThrows(IllegalArgumentException.class,
            () -> validator.validate("3.1", VECTOR.replace("CVSS:3.1", "CVSS:4.0"), SCORE));
        assertTrue(error.getMessage().contains("Prefijo del vector incompatible"));
    }

    @Test
    void rechazaUnaMetricaRepetida() {
        var error = assertThrows(IllegalArgumentException.class,
            () -> validator.validate("3.1", VECTOR + "/AV:N", SCORE));
        assertTrue(error.getMessage().contains("Métrica Base repetida: AV"));
    }

    @Test
    void rechazaUnVectorConUnaMetricaAusente() {
        var error = assertThrows(IllegalArgumentException.class,
            () -> validator.validate("3.1", VECTOR.replace("/A:H", ""), SCORE));
        assertTrue(error.getMessage().contains("las ocho métricas Base"));
    }

    @Test
    void aceptaLasMetricasEnOtroOrden() {
        String reordered = "CVSS:3.1/A:H/I:H/C:H/S:U/UI:N/PR:N/AC:L/AV:N";
        assertDoesNotThrow(() -> validator.validate("3.1", reordered, SCORE));
    }

    @Test
    void aceptaUnaNotaConElMismoValorYDiferenteEscalaDecimal() {
        assertDoesNotThrow(() -> validator.validate("3.1", VECTOR, new BigDecimal("9.80")));
    }
}
