package com.vulnfollowup.nvd;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Limita las peticiones a la NVD: como máximo maxRequests cada windowMillis.
 * La NVD permite 5 peticiones cada 30 segundos sin API key y 50 con API key;
 * si se pasa, responde con error 403 o 503.
 *
 * Se guardan las horas de las últimas peticiones. Si ya hay maxRequests dentro de la ventana,
 * el hilo espera con wait() hasta que la más antigua salga de la ventana.
 */
public class NvdRateLimiter {

    private final int maxRequests;
    private final long windowMillis;
    private final Deque<Long> requestTimes = new ArrayDeque<>();

    public NvdRateLimiter(int maxRequests, long windowMillis) {
        this.maxRequests = maxRequests;
        this.windowMillis = windowMillis;
    }

    // synchronized: varios hilos pueden pedir permiso a la vez y comparten la misma lista.
    public synchronized void acquire() throws InterruptedException {
        while (true) {
            long now = System.currentTimeMillis();

            // Quitar las peticiones que ya han salido de la ventana
            while (!requestTimes.isEmpty() && now - requestTimes.peekFirst() >= windowMillis) {
                requestTimes.pollFirst();
            }

            if (requestTimes.size() < maxRequests) {
                requestTimes.addLast(now);
                return;
            }

            // wait() libera el monitor mientras espera, así otros hilos no se quedan bloqueados en la entrada
            long waitMillis = windowMillis - (now - requestTimes.peekFirst());
            wait(waitMillis);
        }
    }

}
