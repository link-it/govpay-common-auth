package it.govpay.common.auth;

import java.io.IOException;

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
 * request (header {@code Authorization}, cookie sessione, certificato cert).
 *
 * <p>In questo step e' implementato il riconoscimento di {@link AuthType#BASIC};
 * gli altri metodi sono aggiunti negli step successivi.
 */
public class AuthTypeStampingFilter extends OncePerRequestFilter {

    /**
     * Nome dell'attributo della request che porta il {@link AuthType} riconosciuto.
     * Pubblico per consentire ai consumer di accedervi direttamente quando
     * {@link AuthTypeAccessor} non e' praticabile.
     */
    public static final String REQUEST_ATTRIBUTE = "it.govpay.common.auth.authType";

    private static final String BASIC_PREFIX = "Basic ";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (isAuthenticated(auth)) {
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

    /**
     * Riconosce il metodo di autenticazione applicato dalla request.
     * Estendere qui quando si aggiunge un nuovo filter (BEARER, X-API-Key, ...).
     */
    private static AuthType detect(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.regionMatches(true, 0, BASIC_PREFIX, 0, BASIC_PREFIX.length())) {
            return AuthType.BASIC;
        }
        return null;
    }
}
