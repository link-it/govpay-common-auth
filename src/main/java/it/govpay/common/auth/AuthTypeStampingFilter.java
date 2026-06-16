package it.govpay.common.auth;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Objects;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
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
 * request, con due percorsi possibili:
 *
 * <ol>
 *   <li><b>Self-stamping</b>: i filter custom della libreria che hanno auth
 *       success (JsonLogin → FORM, ApiKey → API_KEY, Header → HEADER,
 *       SslHeader → SSL_HEADER) annotano l'attributo direttamente nel loro
 *       {@code successfulAuthentication}. Quando lo stamping filter scorre
 *       la request trova gia' l'attributo settato e lo lascia inalterato.
 *       Questo evita falsi positivi sui filter pre-auth (es. header presente
 *       ma authentication fallita → no stamping).</li>
 *   <li><b>Detection</b> (fallback): per i filter built-in di Spring Security
 *       ({@code BasicAuthenticationFilter}, {@code X509AuthenticationFilter})
 *       che non controlliamo, lo stamping filter deriva l'{@link AuthType}
 *       dal cue della request (header {@code Authorization: Basic},
 *       attributo {@code jakarta.servlet.request.X509Certificate}).</li>
 * </ol>
 *
 * <p><b>Ordine di rilevamento</b> nel fallback (in caso di piu' cue presenti
 * contemporaneamente):
 * <ol>
 *   <li>Preset esplicito (settato da un filter custom su success) — sempre vince</li>
 *   <li>{@link JwtAuthenticationToken} nel context → {@link AuthType#OAUTH2}
 *       (cue forte: tipo di token specifico per resource server JWT)</li>
 *   <li>{@code Authorization: Basic} header → {@link AuthType#BASIC}</li>
 *   <li>{@code Authorization: Bearer} header → {@link AuthType#OAUTH2}
 *       (fallback per casi edge: token Bearer custom non-JWT)</li>
 *   <li>Attributo {@code jakarta.servlet.request.X509Certificate} → {@link AuthType#SSL}</li>
 *   <li>Cookie sessione valido → {@link AuthType#FORM}</li>
 * </ol>
 *
 * <p>Per HEADER, SSL_HEADER, API_KEY il detection fallback verifica la
 * presenza dell'header configurato come decisione last-resort, ma in
 * pratica self-stamping ha sempre la precedenza.
 *
 * <p><b>Decisione su SSL vs SSL_HEADER coesistenti</b>: la presenza
 * dell'attributo X.509 (TLS terminata in Tomcat con clientAuth) ha precedenza
 * sulla presenza dell'header SSL_HEADER (TLS terminata upstream). Edge case
 * teorico: tunneling esotico dove entrambi sono presenti — in pratica nessun
 * deploy reale lo realizza, e l'evidence "backend ha verificato direttamente
 * la mTLS" e' piu' autorevole.
 */
public class AuthTypeStampingFilter extends OncePerRequestFilter {

    /**
     * Nome dell'attributo della request che porta il {@link AuthType} riconosciuto.
     */
    public static final String REQUEST_ATTRIBUTE = "it.govpay.common.auth.authType";

    private static final String BASIC_PREFIX = "Basic ";
    private static final String BEARER_PREFIX = "Bearer ";
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
            AuthType type = detect(request, auth);
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

    private AuthType detect(HttpServletRequest request, Authentication auth) {
        // OAUTH2 (cue forte): il BearerTokenAuthenticationFilter di Spring non
        // self-stamps; pero' il token nel context e' un JwtAuthenticationToken,
        // che non viene mai prodotto da altri filter della chain. Match diretto.
        if (auth instanceof JwtAuthenticationToken) {
            return AuthType.OAUTH2;
        }
        // BASIC: Authorization header (Spring BasicAuthenticationFilter non self-stamps)
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.regionMatches(true, 0, BASIC_PREFIX, 0, BASIC_PREFIX.length())) {
            return AuthType.BASIC;
        }
        // OAUTH2 (fallback): Bearer token custom (non-JWT). Raro in pratica ma
        // copre setup con resource server non-JWT che non producono
        // JwtAuthenticationToken.
        if (authorization != null && authorization.regionMatches(true, 0, BEARER_PREFIX, 0, BEARER_PREFIX.length())) {
            return AuthType.OAUTH2;
        }
        // SSL: X.509 cert a livello TLS (Spring X509AuthenticationFilter non self-stamps)
        if (request.getAttribute(X509_REQUEST_ATTRIBUTE) instanceof X509Certificate[]) {
            return AuthType.SSL;
        }
        // API_KEY: fallback per coppia header presente (in pratica raggiunto solo
        // se ApiKeyAuthenticationFilter non e' montato ma un altro filter ha autenticato).
        if (properties.getApiKey().isEnabled()
                && request.getHeader(properties.getApiKey().getIdHeaderName()) != null
                && request.getHeader(properties.getApiKey().getKeyHeaderName()) != null) {
            return AuthType.API_KEY;
        }
        // HEADER: fallback per uno qualunque dei header configurati
        if (properties.getHeader().isEnabled()) {
            for (String header : properties.getHeader().getPrincipalHeaderNames()) {
                if (request.getHeader(header) != null) {
                    return AuthType.HEADER;
                }
            }
        }
        // SSL_HEADER: fallback per header configurato (proxy-terminated TLS)
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
