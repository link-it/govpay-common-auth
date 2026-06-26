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
 * <p>Scenario in cui un altro componente upstream (es. SAML/SPID handler
 * proprietario, o un controller di login dedicato) ha popolato la sessione
 * con il principal autenticato in un attributo noto.
 * Le request successive presentano il cookie sessione; questo filter ne
 * estrae il principal senza ricorrere a una nuova autenticazione.
 *
 * <p>Se la sessione non esiste o l'attributo e' assente, il filter ritorna
 * {@code null} → la chain salta senza errori.
 *
 * <p><b>Note</b>: al momento legge solo {@code GP_PRINCIPAL} e ricorre comunque alla
 * UDS via {@code sessionUserDetailsService}. Se in futuro emerge un caso d'uso per
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
        request.setAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE_PRINCIPAL, authResult.getName());
    }
}
