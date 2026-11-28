package com.vulnfollowup.scan;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Lanza el escáner como proceso externo con ProcessBuilder y devuelve lo que imprime por pantalla.
 */
public class TrivyRunner {

    private final List<String> command;
    private final String target;
    private final long timeoutSeconds;

    public TrivyRunner(List<String> command, String target, long timeoutSeconds) {
        this.command = command;
        this.target = target;
        this.timeoutSeconds = timeoutSeconds;
    }

    public String run() throws IOException, InterruptedException {
        List<String> fullCommand = new ArrayList<>(command);
        fullCommand.add(target);

        // La salida va a ficheros temporales: si el proceso escribe mucho y nadie lee el pipe,
        // se queda bloqueado.
        File output = File.createTempFile("trivy-", ".json");
        File errors = File.createTempFile("trivy-", ".err");
        try {
            ProcessBuilder builder = new ProcessBuilder(fullCommand);
            builder.redirectOutput(output);
            builder.redirectError(errors);
            Process process = builder.start();

            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                throw new IOException("El escáner tardó más de " + timeoutSeconds + " segundos");
            }
            if (process.exitValue() != 0) {
                throw new IOException("El escáner terminó con código " + process.exitValue() + ": "
                    + Files.readString(errors.toPath()).strip());
            }
            return Files.readString(output.toPath());
        } finally {
            output.delete();
            errors.delete();
        }
    }

}
