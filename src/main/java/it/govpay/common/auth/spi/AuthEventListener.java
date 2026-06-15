package it.govpay.common.auth.spi;

import jakarta.servlet.http.HttpServletRequest;

/**
 * SPI opzionale per ricevere notifica degli eventi di autenticazione gestiti
 * dalla libreria (login riuscito, login fallito, logout). Il consumer puo'
 * registrare un {@code @Component} per inoltrare gli eventi al proprio
 * sottosistema di audit/log/metriche.
 *
 * <p>Tutti i metodi hanno implementazione default no-op: il consumer
 * implementa solo quelli che gli interessano. Se nessun bean di questo tipo
 * e' registrato, la libreria espone un'implementazione no-op di default
 * (vedi {@code GovpayAuthAutoConfiguration}).
 *
 * <p>Le invocazioni avvengono nel thread che ha gestito la request, dopo
 * che Spring Security ha completato la sua parte: il consumer puo' leggere
 * tranquillamente header e attributi dalla {@link HttpServletRequest}. Le
 * implementazioni devono essere veloci (o demandare ad un executor) per non
 * impattare la latenza della response.
 */
public interface AuthEventListener {

    /**
     * Login andato a buon fine.
     *
     * @param principal identificativo dell'utenza autenticata
     * @param authType  tipo di autenticazione applicato dalla chain
     * @param request   request HTTP corrente (header, IP del chiamante, ...)
     */
    default void onLoginSuccess(String principal, AuthType authType, HttpServletRequest request) {
        // default no-op
    }

    /**
     * Login fallito. Il principal puo' essere {@code null} se la request non
     * conteneva proprio le credenziali (es. SSL senza certificato).
     *
     * @param attemptedPrincipal identificativo tentato (puo' essere {@code null})
     * @param authType           tipo di autenticazione applicato dalla chain
     * @param reason             motivo del fallimento
     * @param request            request HTTP corrente
     */
    default void onLoginFailed(String attemptedPrincipal,
                               AuthType authType,
                               FailureReason reason,
                               HttpServletRequest request) {
        // default no-op
    }

    /**
     * Logout esplicito (sessione invalidata su richiesta utente). NON viene
     * invocato per scadenza sessione passiva.
     *
     * @param principal identificativo dell'utenza che ha fatto logout,
     *                  catturato prima dell'invalidazione del context
     * @param request   request HTTP corrente
     */
    default void onLogout(String principal, HttpServletRequest request) {
        // default no-op
    }
}
