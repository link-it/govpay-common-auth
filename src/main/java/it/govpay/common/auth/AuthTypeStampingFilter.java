package it.govpay.common.auth;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Objects;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import it.govpay.common.auth.spi.AuthType;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter che, dopo che Spring Security ha valorizzato il {@code SecurityContext},
 * ispeziona la request e marca il {@link AuthType} con cui l'autenticazione e'
 * avvenuta. Il valore e' salvato come attributo della request
 * ({@value #REQUEST_ATTRIBUTE}) e puo' essere letto dai controller via
 * {@link AuthTypeAccessor}.
 *
 * <p>Replica concettualmente il pattern V1 in cui ciascuna chain valorizzava
 * {@code utenza.autenticazione} con il proprio {@code authType}: qui la
 * "stampatura" e' centralizzata in un unico filter che riconosce il cue della
 * request (header {@code Authorization}, cookie sessione, certificato cert,
 * header pre-auth).
 *
 * <p>Ordine di riconoscimento: preset esplicito da un filter custom (ha
 * sempre la precedenza) &gt; {@code Authorization: Basic} &gt; certificato
 * X.509 client &gt; coppia header API_KEY &gt; header pre-auth HEADER &gt;
 * header pre-auth SSL_HEADER &gt; cookie sessione valido (FORM).
 */
public class AuthTypeStampingFilter extends OncePerRequestFilter {

    /**
     * Nome dell'attributo della request che porta il {@link AuthType} riconosciuto.
     */
    public static final String REQUEST_ATTRIBUTE = "it.govpay.common.auth.authType";

    private static final String BASIC_PREFIX = "Basic ";
    private static final String X509_REQUEST_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

    private final GovpayAuthProperties properties;

    public AuthTypeStampingFilter() {
        this(new GovpayAuthProperties());
    }

    public AuthTypeStampingFilter(GovpayAuthProperties properties) {
        this.properties = Objects.requireNonNull(properties, "properties");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (isAuthenticated(auth) && !(request.getAttribute(REQUEST_ATTRIBUTE) instanceof AuthType)) {
            AuthType type = detect(request);
            if (type != null) {
                request.setAttribute(REQUEST_ATTRIBUTE, type);
            }
        }
        filterChain.doFilter(request, response);
    }

    private static boolean isAuthenticated(Authentication auth) {
        return auth != null
                && auth.isAuthenticated()
                && !(auth instanceof AnonymousAuthenticationToken);
    }

    private AuthType detect(HttpServletRequest request) {
        // BASIC: Authorization header
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.regionMatches(true, 0, BASIC_PREFIX, 0, BASIC_PREFIX.length())) {
            return AuthType.BASIC;
        }
        // SSL: X.509 cert presentato a livello TLS
        if (request.getAttribute(X509_REQUEST_ATTRIBUTE) instanceof X509Certificate[]) {
            return AuthType.SSL;
        }
        // API_KEY: coppia header configurati
        if (properties.getApiKey().isEnabled()
                && request.getHeader(properties.getApiKey().getIdHeaderName()) != null
                && request.getHeader(properties.getApiKey().getKeyHeaderName()) != null) {
            return AuthType.API_KEY;
        }
        // HEADER: principal in header configurato
        if (properties.getHeader().isEnabled()
                && request.getHeader(properties.getHeader().getPrincipalHeaderName()) != null) {
            return AuthType.HEADER;
        }
        // SSL_HEADER: cert subject in header configurato (proxy-terminated TLS)
        if (properties.getSslHeader().isEnabled()
                && request.getHeader(properties.getSslHeader().getPrincipalHeaderName()) != null) {
            return AuthType.SSL_HEADER;
        }
        // FORM: cookie sessione valido
        if (request.getRequestedSessionId() != null && request.isRequestedSessionIdValid()) {
            return AuthType.FORM;
        }
        return null;
    }
}
