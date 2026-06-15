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
 * <p>Porting V1 fedele di {@code it.govpay.rs.v1.authentication.preauth.filter.HeaderPreAuthFilter}:
 * accetta una {@code List<String>} di nomi header, itera in ordine e ritorna
 * il valore del primo non-null. Replica anche
 * {@code exceptionIfHeaderMissing=false} (default V1): nessun header
 * presente → principal {@code null} → la chain salta questo filter senza
 * lanciare eccezioni.
 *
 * <p>Marca esplicitamente {@link AuthType#HEADER} sull'attributo della
 * request dopo authentication success, cosi' {@link AuthTypeStampingFilter}
 * non deve indovinare dal solo cue header.
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
    }
}
