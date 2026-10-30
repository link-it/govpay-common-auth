package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

class LoginRateLimiterTest {

    @Test
    void allowsAttemptsUpToTheLimit() {
        LoginRateLimiter limiter = new LoginRateLimiter(3, Duration.ofMinutes(15));

        assertThat(limiter.tryAcquire("1.2.3.4")).isTrue();
        limiter.recordFailure("1.2.3.4");
        assertThat(limiter.tryAcquire("1.2.3.4")).isTrue();
        limiter.recordFailure("1.2.3.4");
        assertThat(limiter.tryAcquire("1.2.3.4")).isTrue();
        limiter.recordFailure("1.2.3.4");

        assertThat(limiter.tryAcquire("1.2.3.4")).isFalse();
    }

    @Test
    void differentKeysAreIndependent() {
        LoginRateLimiter limiter = new LoginRateLimiter(2, Duration.ofMinutes(15));

        limiter.recordFailure("a");
        limiter.recordFailure("a");
        assertThat(limiter.tryAcquire("a")).isFalse();
        assertThat(limiter.tryAcquire("b")).isTrue();
    }

    @Test
    void resetClearsFailures() {
        LoginRateLimiter limiter = new LoginRateLimiter(2, Duration.ofMinutes(15));

        limiter.recordFailure("a");
        limiter.recordFailure("a");
        assertThat(limiter.tryAcquire("a")).isFalse();

        limiter.reset("a");

        assertThat(limiter.tryAcquire("a")).isTrue();
    }

    @Test
    void slidingWindowExpiresOldFailures() {
        MutableClock clock = new MutableClock(Instant.parse("2026-06-15T10:00:00Z"));
        LoginRateLimiter limiter = new LoginRateLimiter(2, Duration.ofMinutes(15), clock);

        limiter.recordFailure("a");
        limiter.recordFailure("a");
        assertThat(limiter.tryAcquire("a")).isFalse();

        // 16 minuti dopo, le failure escono dalla finestra
        clock.advance(Duration.ofMinutes(16));
        assertThat(limiter.tryAcquire("a")).isTrue();
    }

    @Test
    void rejectsInvalidConstructorParameters() {
        assertThatThrownBy(() -> new LoginRateLimiter(0, Duration.ofMinutes(15)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LoginRateLimiter(5, Duration.ZERO))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LoginRateLimiter(5, null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void tryAcquireDoesNotCreateEntries() {
        LoginRateLimiter limiter = new LoginRateLimiter(2, Duration.ofMinutes(15));

        for (int i = 0; i < 1000; i++) {
            assertThat(limiter.tryAcquire("10.0.0." + i)).isTrue();
        }

        assertThat(limiter.size()).isZero();
    }

    @Test
    void expiredEntryIsRemovedWhenConsulted() {
        MutableClock clock = new MutableClock(Instant.parse("2026-06-15T10:00:00Z"));
        LoginRateLimiter limiter = new LoginRateLimiter(2, Duration.ofMinutes(15), clock);

        limiter.recordFailure("a");
        assertThat(limiter.size()).isEqualTo(1);

        clock.advance(Duration.ofMinutes(16));
        assertThat(limiter.tryAcquire("a")).isTrue();
        assertThat(limiter.size()).isZero();
    }

    @Test
    void periodicSweepRemovesEntriesOfKeysNeverSeenAgain() {
        MutableClock clock = new MutableClock(Instant.parse("2026-06-15T10:00:00Z"));
        LoginRateLimiter limiter = new LoginRateLimiter(2, Duration.ofMinutes(15), clock);

        for (int i = 0; i < 500; i++) {
            limiter.recordFailure("10.0." + (i / 256) + "." + (i % 256));
        }
        assertThat(limiter.size()).isEqualTo(500);

        // Dopo la finestra, il primo accesso con un'altra chiave pulisce la mappa.
        clock.advance(Duration.ofMinutes(16));
        limiter.recordFailure("192.168.1.1");

        assertThat(limiter.size()).isEqualTo(1);
    }

    @Test
    void sweepKeepsEntriesStillInsideTheWindow() {
        MutableClock clock = new MutableClock(Instant.parse("2026-06-15T10:00:00Z"));
        LoginRateLimiter limiter = new LoginRateLimiter(2, Duration.ofMinutes(15), clock);

        limiter.recordFailure("vecchio");
        clock.advance(Duration.ofMinutes(10));
        limiter.recordFailure("recente");
        limiter.recordFailure("recente");
        clock.advance(Duration.ofMinutes(6));

        limiter.recordFailure("altro");

        assertThat(limiter.size()).isEqualTo(2);
        assertThat(limiter.tryAcquire("recente")).isFalse();
        assertThat(limiter.tryAcquire("vecchio")).isTrue();
    }

    @Test
    void failuresPerKeyAreCappedAtMaxAttempts() {
        LoginRateLimiter limiter = new LoginRateLimiter(3, Duration.ofMinutes(15));

        for (int i = 0; i < 10_000; i++) {
            limiter.recordFailure("a");
        }

        assertThat(limiter.tryAcquire("a")).isFalse();
        assertThat(limiter.size()).isEqualTo(1);
    }

    private static class MutableClock extends Clock {
        private Instant now;
        MutableClock(Instant initial) { this.now = initial; }
        void advance(Duration delta) { this.now = this.now.plus(delta); }
        @Override public Instant instant() { return now; }
        @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
    }
}
