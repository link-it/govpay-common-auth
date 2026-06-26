package it.govpay.common.auth;

import java.util.List;
import java.util.Objects;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import it.govpay.common.auth.spi.AuthType;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter pre-auth che estrae il principal dell'utenza da uno tra una lista di
 * header HTTP configurabili (fallback in ordine). Tipico scenario: reverse
 * proxy che ha gia' autenticato l'utente upstream e propaga il suo
 * identificativo (es. CN del cert, e-mail, username) via header.
 *
 * <p>Accetta una {@code List<String>} di nomi header, itera in ordine e ritorna
 * il valore del primo non-null. Replica anche
 * {@code exceptionIfHeaderMissing=false} (default): nessun header
 * presente → principal {@code null} → la chain salta questo filter senza
 * lanciare eccezioni.
 *
 * <p><b>Self-stamping di {@link AuthType#HEADER}</b> in
 * {@code successfulAuthentication}: necessario per il caso
 * "HEADER + Basic stesso user". Spring {@link AbstractPreAuthenticatedProcessingFilter}
 * chiama {@code successfulAuthentication} <b>solo</b> se ha agito
 * (i.e. {@code requiresAuthentication=true}: context vuoto o
 * {@code checkForPrincipalChanges=true}), quindi il self-stamp marca solo i
 * cicli "ho effettivamente autenticato". I cicli skippati (es. session
 * preauth gia' nel context per lo stesso principal) non self-stampano e
 * l'{@link AuthTypeStampingFilter} cade sui fallback corretti
 * (session attribute persisted / cue cookie sessione).
 */
public class HeaderPreAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

    private final List<String> principalHeaderNames;

    public HeaderPreAuthenticationFilter(List<String> principalHeaderNames) {
        Objects.requireNonNull(principalHeaderNames, "principalHeaderNames");
        if (principalHeaderNames.isEmpty()) {
            throw new IllegalArgumentException("principalHeaderNames must not be empty");
        }
        this.principalHeaderNames = List.copyOf(principalHeaderNames);
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        for (String header : principalHeaderNames) {
            String value = request.getHeader(header);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "N/A";
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            Authentication authResult) throws java.io.IOException, jakarta.servlet.ServletException {
        super.successfulAuthentication(request, response, authResult);
        request.setAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE, AuthType.HEADER);
        request.setAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE_PRINCIPAL, authResult.getName());
    }
}
