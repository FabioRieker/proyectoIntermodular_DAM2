package com.vulnfollowup.scan;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;

// Los tests usan "sh" en lugar de trivy para no depender de tenerlo instalado.
class TrivyRunnerTest {

    @Test
    void devuelveLaSalidaDelProceso() throws Exception {
        TrivyRunner runner = new TrivyRunner(List.of("sh"), "src/test/resources/scanner/fake-trivy.sh", 10);

        String output = runner.run();

        assertTrue(output.contains("CVE-2024-0001"));
    }

    @Test
    void codigoDeSalidaDistintoDeCeroEsError() {
        TrivyRunner runner = new TrivyRunner(List.of("sh", "-c", "echo fallo >&2; exit 1"), "x", 10);

        IOException e = assertThrows(IOException.class, runner::run);
        assertTrue(e.getMessage().contains("fallo"));
    }

    @Test
    void procesoQueTardaDemasiadoSeCancela() {
        TrivyRunner runner = new TrivyRunner(List.of("sleep"), "30", 1);

        IOException e = assertThrows(IOException.class, runner::run);
        assertTrue(e.getMessage().contains("tardó más de 1 segundos"));
    }

}
