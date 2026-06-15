package it.govpay.common.auth;

import java.io.IOException;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter che gestisce l'autenticazione API_KEY: legge i due header configurati
 * ({@code X-Govpay-API-ID} e {@code X-Govpay-API-Key}) e li sottopone al
 * proprio {@link AuthenticationManager} come {@link UsernamePasswordAuthenticationToken}
 * (id=username, key=password).
 *
 * <p>Porting V1: {@code it.govpay.rs.v1.authentication.filter.ApiKeyBasicAuthFilter},
 * con failure-handling semplificato: se gli header sono assenti, il filter
 * non agisce (passa al filter successivo). Se sono presenti ma l'auth
 * fallisce, il SecurityContext resta vuoto e l'eventuale 401 viene emesso
 * dall'{@link org.springframework.security.web.AuthenticationEntryPoint}
 * della chain.
 */
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(ApiKeyAuthenticationFilter.class);

    private final String idHeaderName;
    private final String keyHeaderName;
    private final AuthenticationManager authenticationManager;

    public ApiKeyAuthenticationFilter(String idHeaderName, String keyHeaderName,
                                      AuthenticationManager authenticationManager) {
        this.idHeaderName = Objects.requireNonNull(idHeaderName, "idHeaderName");
        this.keyHeaderName = Objects.requireNonNull(keyHeaderName, "keyHeaderName");
        this.authenticationManager = Objects.requireNonNull(authenticationManager, "authenticationManager");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        String id = request.getHeader(idHeaderName);
        String key = request.getHeader(keyHeaderName);
        if (id == null || id.isBlank() || key == null || key.isBlank()) {
            chain.doFilter(request, response);
            return;
        }
        UsernamePasswordAuthenticationToken authRequest =
                UsernamePasswordAuthenticationToken.unauthenticated(id, key);
        try {
            Authentication authResult = authenticationManager.authenticate(authRequest);
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authResult);
            SecurityContextHolder.setContext(context);
        } catch (AuthenticationException ex) {
            log.debug("Autenticazione API_KEY fallita per id={}", id, ex);
            SecurityContextHolder.clearContext();
        }
        chain.doFilter(request, response);
    }
}
