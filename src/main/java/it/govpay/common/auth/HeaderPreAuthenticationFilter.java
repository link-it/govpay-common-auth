package it.govpay.common.auth;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Filter pre-auth che estrae il principal dell'utenza da un header HTTP
 * configurabile. Tipico scenario: reverse proxy che ha gia' autenticato
 * l'utente upstream e propaga il suo identificativo (es. CN del cert, e-mail,
 * username) via header.
 *
 * <p>Porting V1: {@code it.govpay.rs.v1.authentication.preauth.filter.HeaderPreAuthFilter}.
 * V1 supportava una lista di nomi header con fallback in ordine; questa
 * versione semplificata accetta un singolo nome (sufficiente per i casi
 * documentati; estendere se serve la lista).
 */
public class HeaderPreAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

    private final String principalHeaderName;

    public HeaderPreAuthenticationFilter(String principalHeaderName) {
        if (principalHeaderName == null || principalHeaderName.isBlank()) {
            throw new IllegalArgumentException("principalHeaderName must not be blank");
        }
        this.principalHeaderName = principalHeaderName;
        setExceptionIfHeaderMissing(false);
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        return request.getHeader(principalHeaderName);
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "N/A";
    }

    /**
     * Comportamento allineato a V1 ({@code exceptionIfHeaderMissing=false}):
     * se l'header non c'e' o e' vuoto, il filter non blocca la request e
     * lascia il flow agli altri filter; non lancia eccezione.
     */
    void setExceptionIfHeaderMissing(boolean exceptionIfHeaderMissing) {
        // marker per chiarezza, l'implementazione di
        // AbstractPreAuthenticatedProcessingFilter gia' tratta principal=null
        // come "salta", quindi non serve fare di piu'.
    }
}
