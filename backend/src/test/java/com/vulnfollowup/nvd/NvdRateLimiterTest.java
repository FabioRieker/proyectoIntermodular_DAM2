package com.vulnfollowup.nvd;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.junit.jupiter.api.Test;

class NvdRateLimiterTest {

    @Test
    void lasPrimerasPeticionesNoEsperan() throws Exception {
        NvdRateLimiter limiter = new NvdRateLimiter(3, 1000);

        long start = System.currentTimeMillis();
        limiter.acquire();
        limiter.acquire();
        limiter.acquire();

        assertTrue(System.currentTimeMillis() - start < 200);
    }

    @Test
    void laSiguientePeticionEsperaAQueTermineLaVentana() throws Exception {
        NvdRateLimiter limiter = new NvdRateLimiter(2, 500);

        long start = System.currentTimeMillis();
        limiter.acquire();
        limiter.acquire();
        limiter.acquire();

        assertTrue(System.currentTimeMillis() - start >= 450);
    }

    @Test
    void conVariosHilosNuncaSePasaDelLimite() throws Exception {
        NvdRateLimiter limiter = new NvdRateLimiter(3, 400);
        List<Long> times = Collections.synchronizedList(new ArrayList<>());

        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < 6; i++) {
            threads.add(new Thread(() -> {
                try {
                    limiter.acquire();
                    times.add(System.currentTimeMillis());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }
        for (Thread t : threads) {
            t.start();
        }
        for (Thread t : threads) {
            t.join();
        }

        // 6 peticiones con un límite de 3: la 4ª tiene que ir al menos ~400 ms después de la 1ª
        assertEquals(6, times.size());
        Collections.sort(times);
        assertTrue(times.get(3) - times.get(0) >= 350, "Tiempos: " + times);
    }

}
