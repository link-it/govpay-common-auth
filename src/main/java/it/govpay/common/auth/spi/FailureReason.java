package it.govpay.common.auth.spi;

/**
 * Motivo del fallimento di un tentativo di autenticazione.
 *
 * <p>Esposto a {@link AuthEventListener#onLoginFailed} per consentire al
 * consumer di tracciare l'esito su audit con motivo strutturato (cfr.
 * {@code PROFILO_LOGIN_FAILED} in issue link-it/govpay-console-api#10).
 */
public enum FailureReason {
    /** Credenziali non valide (password errata o principal inesistente). */
    BAD_CREDENTIALS,
    /** Utenza riconosciuta ma disabilitata. */
    DISABLED,
    /** Rate-limit superato sull'IP/utenza chiamante. */
    RATE_LIMITED,
    /** Errore interno durante il processo di autenticazione. */
    INTERNAL_ERROR
}
