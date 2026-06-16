package it.govpay.common.auth;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import it.govpay.common.auth.spi.AuthType;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

/**
 * Filter pre-auth che legge il principal da un attributo della
 * {@link HttpSession} corrente.
 *
 * <p>Porting V1 fedele di {@code it.govpay.rs.v1.authentication.preauth.filter.SessionPrincipalExtractorPreAuthFilter}:
 * scenario in cui un altro componente upstream (es. SAML/SPID handler
 * proprietario, o un controller di login dedicato) ha popolato la sessione
 * con il principal autenticato in un attributo noto (V1: {@code "GP_PRINCIPAL"}).
 * Le request successive presentano il cookie sessione; questo filter ne
 * estrae il principal senza ricorrere a una nuova autenticazione.
 *
 * <p>Se la sessione non esiste o l'attributo e' assente, il filter ritorna
 * {@code null} → la chain salta senza errori.
 *
 * <p><b>Note V1 non portate</b>: V1 definisce due costanti correlate
 * ({@code SESSION_PRINCIPAL_ATTRIBUTE_NAME = "GP_PRINCIPAL"} e
 * {@code SESSION_PRINCIPAL_OBJECT_ATTRIBUTE_NAME = "GP_PRINCIPAL_OBJECT"}). Il
 * filter V1 legge solo {@code GP_PRINCIPAL}; la seconda costante esiste ma
 * il suo uso downstream non e' chiaro (probabilmente porta l'utenza gia'
 * risolta come oggetto Java, per saltare il re-lookup via UDS). V2 al
 * momento legge solo {@code GP_PRINCIPAL} e ricorre comunque alla UDS via
 * {@code sessionUserDetailsService}. Se in futuro emerge un caso d'uso per
 * il bypass del lookup, esponiamo una property dedicata.
 */
public class SessionPreAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

    private static final Logger log = LoggerFactory.getLogger(SessionPreAuthenticationFilter.class);

    private final String sessionPrincipalAttributeName;

    public SessionPreAuthenticationFilter(String sessionPrincipalAttributeName) {
        this.sessionPrincipalAttributeName = Objects.requireNonNull(
                sessionPrincipalAttributeName, "sessionPrincipalAttributeName");
        if (sessionPrincipalAttributeName.isBlank()) {
            throw new IllegalArgumentException("sessionPrincipalAttributeName must not be blank");
        }
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        Object principal = session.getAttribute(sessionPrincipalAttributeName);
        log.debug("SESSION principal letto da attributo [{}]: [{}]",
                sessionPrincipalAttributeName, principal);
        return principal;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "N/A";
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            Authentication authResult) throws java.io.IOException, ServletException {
        super.successfulAuthentication(request, response, authResult);
        request.setAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE, AuthType.SESSION);
    }
}
