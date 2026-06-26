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
 * <p>La stampatura segue un pattern hybrid che combina <b>self-stamping
 * dei filter custom</b> e <b>detection dai cue della request</b>:
 *
 * <ul>
 *   <li><b>Self-stamping</b>: i filter custom della libreria che hanno
 *       autenticato (ApiKey, Header, SslHeader, Spid, Session, Ldap,
 *       JsonLogin) marcano sulla request la coppia
 *       {@code (AuthType, principal)} via {@link #REQUEST_ATTRIBUTE} +
 *       {@link #REQUEST_ATTRIBUTE_PRINCIPAL}. JsonLogin persiste la
 *       coppia anche su {@code HttpSession} ({@link #SESSION_ATTRIBUTE} +
 *       {@link #SESSION_ATTRIBUTE_PRINCIPAL}), cosi' le request
 *       successive con cookie sessione attivo onorano il marker.</li>
 *   <li><b>Detection</b>: per i filter built-in di Spring
 *       ({@code BasicAuthenticationFilter}, {@code X509AuthenticationFilter},
 *       {@code BearerTokenAuthenticationFilter}) che non possono
 *       self-stampare, l'{@link AuthType} viene derivato dai cue della
 *       request.</li>
 * </ul>
 *
 * <p><b>Coerenza preset / principal</b>: ogni marker viene confrontato
 * con il principal corrente del {@code SecurityContext}. Se un filter
 * downstream sovrascrive il context con un principal diverso, il marker
 * precedente diventa "stale" e viene scartato — lo stamping ripiega sui
 * cue, riflettendo il metodo effettivamente attivo.
 *
 * <p><b>Ordine di rilevamento</b> nel detect:
 * <ol>
 *   <li>Preset request coerente col principal corrente → quello vince.</li>
 *   <li>{@link JwtAuthenticationToken} nel context → {@link AuthType#OAUTH2}.</li>
 *   <li>Session attribute coerente col principal corrente → quello vince.</li>
 *   <li>{@code Authorization: Basic} → {@link AuthType#BASIC}
 *       (copre anche LDAP, che usa Basic come trasporto).</li>
 *   <li>{@code Authorization: Bearer} → {@link AuthType#OAUTH2}
 *       (fallback per token Bearer custom non-JWT).</li>
 *   <li>Attributo {@code jakarta.servlet.request.X509Certificate} →
 *       {@link AuthType#SSL}.</li>
 *   <li>API key headers configurati → {@link AuthType#API_KEY}.</li>
 *   <li>HEADER pre-auth configurati → {@link AuthType#HEADER}.</li>
 *   <li>SSL_HEADER configurato → {@link AuthType#SSL_HEADER}.</li>
 *   <li>SPID header configurato → {@link AuthType#SPID}.</li>
 *   <li>Attributo {@code HttpSession} SESSION configurato →
 *       {@link AuthType#SESSION}.</li>
 *   <li>Cookie sessione valido → {@link AuthType#FORM}.</li>
 * </ol>
 *
 * <p><b>SSL vs SSL_HEADER coesistenti</b>: la presenza dell'attributo
 * X.509 (TLS terminata in Tomcat con clientAuth) ha precedenza sulla
 * presenza dell'header SSL_HEADER (TLS terminata upstream). In pratica
 * non c'e' deploy che li compresenta, e l'evidenza "backend ha verificato
 * direttamente la mTLS" e' piu' autorevole del cue header.
 */
public class AuthTypeStampingFilter extends OncePerRequestFilter {

    /**
     * Nome dell'attributo della request che porta il {@link AuthType} riconosciuto.
     */
    public static final String REQUEST_ATTRIBUTE = "it.govpay.common.auth.authType";

    /**
     * Principal "ufficiale" del marker request: usato per invalidare il preset
     * quando un filter downstream sovrascrive il {@code SecurityContext} con un
     * principal diverso (es. {@code ApiKey: apikey-id} → {@code BasicAuth: alice}).
     * Se il principal corrente non coincide con questo marker, il preset e'
     * stale e il detect cade sui cue della request.
     */
    public static final String REQUEST_ATTRIBUTE_PRINCIPAL = "it.govpay.common.auth.authType.principal";

    /**
     * Nome dell'attributo della {@link jakarta.servlet.http.HttpSession} che
     * porta l'{@link AuthType} con cui la sessione e' stata inizialmente
     * autenticata. Usato sulle request successive al login session-based
     * (FORM) per ritornare l'AuthType corretto invece di cadere su un cue
     * potenzialmente ingannevole (es. {@code Authorization: Basic <stesso user>}
     * che {@code BasicAuthenticationFilter} skippa con {@code authenticationIsRequired=false}).
     */
    public static final String SESSION_ATTRIBUTE = "it.govpay.common.auth.authType";

    /** Principal del marker session — stesso pattern di {@link #REQUEST_ATTRIBUTE_PRINCIPAL}. */
    public static final String SESSION_ATTRIBUTE_PRINCIPAL = "it.govpay.common.auth.authType.principal";

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
        if (isAuthenticated(auth)) {
            // Sempre re-detect: un eventuale preset request potrebbe essere
            // stale (filter custom ha autenticato un principal, ma un filter
            // downstream lo ha sovrascritto). Il detect verifica la
            // coerenza preset/principal e cade sui cue se serve.
            AuthType type = detect(request, auth);
            if (type != null) {
                request.setAttribute(REQUEST_ATTRIBUTE, type);
                request.setAttribute(REQUEST_ATTRIBUTE_PRINCIPAL, auth.getName());
            } else {
                // Preset stale e nessun cue valido: pulisci marker spuri
                request.removeAttribute(REQUEST_ATTRIBUTE);
                request.removeAttribute(REQUEST_ATTRIBUTE_PRINCIPAL);
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
        String currentPrincipal = auth.getName();

        // 1. Preset request coerente: un filter custom (ApiKey/Header/...) ha
        //    self-stampato e il principal corrente coincide → quello vince.
        if (request.getAttribute(REQUEST_ATTRIBUTE) instanceof AuthType presetType) {
            Object presetPrincipal = request.getAttribute(REQUEST_ATTRIBUTE_PRINCIPAL);
            if (java.util.Objects.equals(presetPrincipal, currentPrincipal)) {
                return presetType;
            }
            // Preset stale (filter downstream ha sovrascritto): cade ai cue.
        }

        // 2. OAUTH2 (cue forte): JwtAuthenticationToken nel context.
        if (auth instanceof JwtAuthenticationToken) {
            return AuthType.OAUTH2;
        }

        // 3. Session attribute persisted coerente: copre le request
        //    successive in cui SecurityContext viene caricato dalla session
        //    senza che alcun filter custom ri-autentichi (es. FORM su request
        //    successiva, anche se sulla stessa request arriva Authorization:
        //    Basic <stesso user> che BasicAuthFilter skippa).
        jakarta.servlet.http.HttpSession session = request.getSession(false);
        if (session != null
                && session.getAttribute(SESSION_ATTRIBUTE) instanceof AuthType sessionType
                && java.util.Objects.equals(session.getAttribute(SESSION_ATTRIBUTE_PRINCIPAL), currentPrincipal)) {
            return sessionType;
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
        // SPID: header dedicato configurato (proxy SAML/SPID che inietta il
        // codice fiscale del cittadino autenticato)
        if (properties.getSpid().isEnabled()
                && properties.getSpid().getPrincipalHeaderName() != null
                && request.getHeader(properties.getSpid().getPrincipalHeaderName()) != null) {
            return AuthType.SPID;
        }
        // SESSION: attributo HttpSession popolato da componente esterno (es.
        // un controller di login proprietario che ha salvato il principal).
        // Precede il fallback FORM, che si limita a riconoscere "sessione valida".
        jakarta.servlet.http.HttpSession existingSession = request.getSession(false);
        if (existingSession != null
                && properties.getSession().isEnabled()
                && existingSession.getAttribute(properties.getSession().getSessionPrincipalAttributeName()) != null) {
            return AuthType.SESSION;
        }
        // FORM: cookie sessione valido
        if (request.getRequestedSessionId() != null && request.isRequestedSessionIdValid()) {
            return AuthType.FORM;
        }
        return null;
    }
}
