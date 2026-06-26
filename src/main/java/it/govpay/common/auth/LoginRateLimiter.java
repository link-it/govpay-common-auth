package it.govpay.common.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.ConcurrentMap;

/**
 * Rate limiter in-memory per i tentativi falliti di login. Implementa una
 * sliding window per chiave (tipicamente IP del chiamante).
 *
 * <p>Thread-safe. Adatto a deploy single-node; in caso di deploy multi-node
 * la finestra e' locale al singolo nodo e quindi N * max attempts globali.
 * Sufficiente come prima difesa, in attesa di un eventuale rate limiter
 * distribuito.
 */
public class LoginRateLimiter {

    private final int maxAttempts;
    private final Duration window;
    private final Clock clock;
    private final ConcurrentMap<String, Deque<Instant>> failures = new ConcurrentHashMap<>();

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
    }

    /**
     * Verifica se la chiave puo' ancora tentare il login.
     *
     * @return {@code true} se la chiave ha ancora tentativi disponibili
     *         nella finestra; {@code false} se la soglia e' stata superata.
     */
    public boolean tryAcquire(String key) {
        Deque<Instant> queue = failures.computeIfAbsent(key, k -> new ConcurrentLinkedDeque<>());
        Instant now = clock.instant();
        Instant cutoff = now.minus(window);
        synchronized (queue) {
            while (!queue.isEmpty() && queue.peekFirst().isBefore(cutoff)) {
                queue.pollFirst();
            }
            return queue.size() < maxAttempts;
        }
    }

    /**
     * Registra un tentativo fallito per la chiave. Da chiamare dopo
     * authentication failed, non sui successi.
     */
    public void recordFailure(String key) {
        Deque<Instant> queue = failures.computeIfAbsent(key, k -> new ConcurrentLinkedDeque<>());
        synchronized (queue) {
            queue.offerLast(clock.instant());
        }
    }

    /**
     * Reset esplicito (utile a fine login riuscito o nei test).
     */
    public void reset(String key) {
        failures.remove(key);
    }
}
