package it.govpay.common.auth;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Cattura il nome del principal autenticato e lo salva come attributo della
 * request ({@value #REQUEST_ATTRIBUTE}), sopravvivendo al clear del
 * {@code SecurityContext} che Spring Security fa a fine chain. Cosi' i
 * filter o handler che gestiscono il logging tardivo (es. {@code finally}
 * di un servlet filter registrato fuori dalla security chain) possono
 * leggere il principal dopo che Spring l'ha gia' rimosso.
 *
 * <p>Spostato in libreria perche' e' un pattern comune ai consumer
 * (originariamente in console-api {@code it.govpay.console.security.PrincipalCaptureFilter}):
 * il filter viene inserito dalla {@link GovpaySecurityFilterChainAutoConfiguration}
 * automaticamente dopo {@link AuthTypeStampingFilter}, senza wiring custom
 * lato consumer.
 */
public class PrincipalCaptureFilter extends OncePerRequestFilter {

    /** Nome dell'attributo della request che porta il principal catturato. */
    public static final String REQUEST_ATTRIBUTE = "it.govpay.common.auth.principal";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && auth.getName() != null) {
            request.setAttribute(REQUEST_ATTRIBUTE, auth.getName());
        }
        filterChain.doFilter(request, response);
    }
}
