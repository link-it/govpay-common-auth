package it.govpay.common.auth;

import java.io.IOException;
import java.net.URI;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import tools.jackson.databind.ObjectMapper;

import it.govpay.common.auth.spi.AuthEventListener;
import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.AuthenticationDetailsContributor;
import it.govpay.common.auth.spi.FailureReason;
import it.govpay.common.auth.spi.JsonLoginResponseWriter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter custom per {@code POST /auth/login} con body JSON
 * {@code {"username":"...","password":"..."}}. Sostituisce {@code formLogin}
 * di Spring Security che accetta solo body form-urlencoded.
 *
 * <p>Pipeline:
 * <ol>
 *   <li>Match path/metodo;
 *   <li>Pre-check rate-limit per IP del chiamante (429 se superato);
 *   <li>Parsing body JSON in {@link JsonLoginRequest};
 *   <li>Autenticazione via {@code AuthenticationManager} con
 *       {@link UsernamePasswordAuthenticationToken};
 *   <li>Su successo: notifica {@link AuthEventListener#onLoginSuccess},
 *       reset rate-limit per quella chiave, scrive body via
 *       {@link JsonLoginResponseWriter}, mantiene la sessione (gia' creata
 *       da Spring Security per via di {@code SessionCreationPolicy.IF_REQUIRED});
 *   <li>Su fallimento: registra failure nel rate-limit, notifica
 *       {@link AuthEventListener#onLoginFailed} con {@link FailureReason},
 *       scrive 401 problem+json.
 * </ol>
 *
 * <p>Da configurare con {@code AuthenticationManager} dedicato (quello del
 * provider FORM), success handler e failure handler default-implementati
 * dentro questa classe stessa per semplicita'.
 */
public class JsonUsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private static final Logger log = LoggerFactory.getLogger(JsonUsernamePasswordAuthenticationFilter.class);

    /**
     * Nome dell'attributo di request in cui {@link #attemptAuthentication}
     * stampa l'{@code username} parsato dal body, cosi' che
     * {@link #unsuccessfulAuthentication} possa propagarlo come
     * {@code attemptedPrincipal} all'{@link AuthEventListener#onLoginFailed}
     * (l'{@link AuthenticationException} sollevata dal manager non porta lo
     * username originale).
     */
    static final String ATTEMPTED_USERNAME_ATTRIBUTE = "it.govpay.common.auth.attemptedUsername";

    private final ObjectMapper objectMapper;
    private final JsonLoginResponseWriter responseWriter;
    private final AuthEventListener eventListener;
    private final LoginRateLimiter rateLimiter;
    private final AuthenticationDetailsContributor detailsContributor;

    public JsonUsernamePasswordAuthenticationFilter(String loginPath,
                                                    ObjectMapper objectMapper,
                                                    JsonLoginResponseWriter responseWriter,
                                                    AuthEventListener eventListener,
                                                    LoginRateLimiter rateLimiter,
                                                    AuthenticationDetailsContributor detailsContributor) {
        super(loginMatcher(loginPath));
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.responseWriter = Objects.requireNonNull(responseWriter, "responseWriter");
        this.eventListener = Objects.requireNonNull(eventListener, "eventListener");
        this.rateLimiter = Objects.requireNonNull(rateLimiter, "rateLimiter");
        this.detailsContributor = Objects.requireNonNull(detailsContributor, "detailsContributor");
        // I default di AbstractAuthenticationProcessingFilter sono
        // SavedRequestAwareAuthenticationSuccessHandler (302 a / o saved URL) e
        // SimpleUrlAuthenticationFailureHandler (302 a /error). Per un endpoint
        // JSON dobbiamo restare a 200 e a 401 problem+json: sovrascriviamo con
        // no-op handler — il body lo scriviamo in successfulAuthentication /
        // unsuccessfulAuthentication direttamente.
        setAuthenticationSuccessHandler((req, res, auth) -> { /* no redirect */ });
        setAuthenticationFailureHandler((req, res, ex) -> { /* no redirect */ });
    }

    private static RequestMatcher loginMatcher(String loginPath) {
        return PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, loginPath);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        String ip = clientIp(request);
        if (!rateLimiter.tryAcquire(ip)) {
            eventListener.onLoginFailed(null, AuthType.FORM, FailureReason.RATE_LIMITED, request);
            writeProblem(response, HttpStatus.TOO_MANY_REQUESTS,
                    "Troppi tentativi di login. Riprovare piu' tardi.",
                    URI.create(request.getRequestURI()));
            return null;
        }

        JsonLoginRequest body;
        try {
            body = objectMapper.readValue(request.getInputStream(), JsonLoginRequest.class);
        } catch (Exception e) {
            log.debug("Body JSON di /auth/login non parsabile", e);
            eventListener.onLoginFailed(null, AuthType.FORM, FailureReason.BAD_CREDENTIALS, request);
            writeProblem(response, HttpStatus.BAD_REQUEST,
                    "Body JSON non valido. Atteso {\"username\":\"...\",\"password\":\"...\"}.",
                    URI.create(request.getRequestURI()));
            return null;
        }

        if (body == null || body.username() == null || body.password() == null) {
            eventListener.onLoginFailed(body == null ? null : body.username(),
                    AuthType.FORM, FailureReason.BAD_CREDENTIALS, request);
            writeProblem(response, HttpStatus.BAD_REQUEST,
                    "Campi 'username' e 'password' obbligatori.",
                    URI.create(request.getRequestURI()));
            return null;
        }

        // Stampa l'username sul request attribute prima del manager: se il
        // manager solleva AuthenticationException (bad creds / disabled),
        // unsuccessfulAuthentication ce lo recupera per l'audit
        // PROFILO_LOGIN_FAILED.
        request.setAttribute(ATTEMPTED_USERNAME_ATTRIBUTE, body.username());
        UsernamePasswordAuthenticationToken token =
                UsernamePasswordAuthenticationToken.unauthenticated(body.username(), body.password());
        token.setDetails(detailsContributor.buildDetails(request, AuthType.FORM));
        return getAuthenticationManager().authenticate(token);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
        rateLimiter.reset(clientIp(request));
        request.setAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE, AuthType.FORM);
        // Forza la materializzazione del CSRF token (lazy: CsrfFilter mette in
        // request attribute un SupplierCsrfToken, ma la persistenza in cookie
        // avviene solo al primo getToken()). Cosi' il frontend riceve
        // XSRF-TOKEN sulla stessa response del login.
        Object csrf = request.getAttribute(org.springframework.security.web.csrf.CsrfToken.class.getName());
        if (csrf instanceof org.springframework.security.web.csrf.CsrfToken token) {
            token.getToken();
        }
        eventListener.onLoginSuccess(authResult.getName(), AuthType.FORM, request);
        response.setStatus(HttpStatus.OK.value());
        responseWriter.writeSuccessBody(response, authResult);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
                                              HttpServletResponse response,
                                              AuthenticationException failed) throws IOException, ServletException {
        super.unsuccessfulAuthentication(request, response, failed);
        rateLimiter.recordFailure(clientIp(request));
        String attempted = extractAttemptedUsername(request);
        FailureReason reason = (failed instanceof DisabledException)
                ? FailureReason.DISABLED
                : FailureReason.BAD_CREDENTIALS;
        eventListener.onLoginFailed(attempted, AuthType.FORM, reason, request);
        writeProblem(response, HttpStatus.UNAUTHORIZED,
                "Credenziali non valide.",
                URI.create(request.getRequestURI()));
    }

    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            return (comma < 0 ? forwarded : forwarded.substring(0, comma)).trim();
        }
        return request.getRemoteAddr();
    }

    private String extractAttemptedUsername(HttpServletRequest request) {
        Object preset = request.getAttribute(ATTEMPTED_USERNAME_ATTRIBUTE);
        return preset instanceof String s ? s : null;
    }

    private void writeProblem(HttpServletResponse response, HttpStatus status, String detail, URI instance)
            throws IOException {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setTitle(status.getReasonPhrase());
        problem.setInstance(instance);
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), problem);
    }
}
