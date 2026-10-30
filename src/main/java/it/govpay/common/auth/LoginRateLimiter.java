package it.govpay.common.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Rate limiter in-memory per i tentativi falliti di login. Implementa una
 * sliding window per chiave (tipicamente IP del chiamante).
 *
 * <p>Thread-safe. Adatto a deploy single-node; in caso di deploy multi-node
 * la finestra e' locale al singolo nodo e quindi N * max attempts globali.
 * Sufficiente come prima difesa, in attesa di un eventuale rate limiter
 * distribuito.
 *
 * <p>Memoria limitata: per ogni chiave si tengono al massimo {@code maxAttempts}
 * istanti, {@link #tryAcquire} non crea voci e le voci senza tentativi nella
 * finestra vengono rimosse, sia quando la chiave viene consultata sia con una
 * pulizia di tutta la mappa eseguita al piu' una volta per finestra. Restano
 * quindi solo le chiavi con tentativi falliti negli ultimi {@code window}.
 * Tutti gli accessi a una voce passano da {@code compute*} della mappa, che li
 * serializza per chiave.
 */
public class LoginRateLimiter {

    private final int maxAttempts;
    private final Duration window;
    private final Clock clock;
    private final ConcurrentMap<String, Deque<Instant>> failures = new ConcurrentHashMap<>();
    private final AtomicReference<Instant> nextSweep;

    public LoginRateLimiter(int maxAttempts, Duration window) {
        this(maxAttempts, window, Clock.systemUTC());
    }

    LoginRateLimiter(int maxAttempts, Duration window, Clock clock) {
        if (maxAttempts <= 0) {
            throw new IllegalArgumentException("maxAttempts must be positive");
        }
        if (window == null || window.isZero() || window.isNegative()) {
            throw new IllegalArgumentException("window must be a positive Duration");
        }
        this.maxAttempts = maxAttempts;
        this.window = window;
        this.clock = clock;
        this.nextSweep = new AtomicReference<>(clock.instant().plus(window));
    }

    /**
     * Verifica se la chiave puo' ancora tentare il login.
     *
     * @return {@code true} se la chiave ha ancora tentativi disponibili
     *         nella finestra; {@code false} se la soglia e' stata superata.
     */
    public boolean tryAcquire(String key) {
        Instant now = clock.instant();
        sweepIfDue(now);
        Instant cutoff = now.minus(window);
        int[] size = {0};
        failures.computeIfPresent(key, (k, queue) -> {
            prune(queue, cutoff);
            size[0] = queue.size();
            return queue.isEmpty() ? null : queue;
        });
        return size[0] < maxAttempts;
    }

    /**
     * Registra un tentativo fallito per la chiave. Da chiamare dopo
     * authentication failed, non sui successi.
     */
    public void recordFailure(String key) {
        Instant now = clock.instant();
        sweepIfDue(now);
        Instant cutoff = now.minus(window);
        failures.compute(key, (k, queue) -> {
            Deque<Instant> q = queue == null ? new ArrayDeque<>() : queue;
            prune(q, cutoff);
            q.offerLast(now);
            // Per decidere bastano gli ultimi maxAttempts tentativi.
            while (q.size() > maxAttempts) {
                q.pollFirst();
            }
            return q;
        });
    }

    /**
     * Reset esplicito (utile a fine login riuscito o nei test).
     */
    public void reset(String key) {
        failures.remove(key);
    }

    /** Numero di chiavi tenute in memoria (per i test). */
    int size() {
        return failures.size();
    }

    private static void prune(Deque<Instant> queue, Instant cutoff) {
        while (!queue.isEmpty() && queue.peekFirst().isBefore(cutoff)) {
            queue.pollFirst();
        }
    }

    /** Rimuove le voci senza tentativi nella finestra, al piu' una volta per finestra. */
    private void sweepIfDue(Instant now) {
        Instant due = nextSweep.get();
        if (now.isBefore(due) || !nextSweep.compareAndSet(due, now.plus(window))) {
            return;
        }
        Instant cutoff = now.minus(window);
        for (String key : failures.keySet()) {
            failures.computeIfPresent(key, (k, queue) -> {
                prune(queue, cutoff);
                return queue.isEmpty() ? null : queue;
            });
        }
    }
}
