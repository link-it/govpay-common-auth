package it.govpay.common.auth;

import java.io.IOException;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.AuthenticationDetailsContributor;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter che intercetta l'header {@code Authorization: Basic ...} e tenta
 * l'autenticazione tramite un {@code AuthenticationManager} dedicato che
 * usa {@code LdapAuthenticationProvider}.
 *
 * <p>Porting V1 della sezione {@code BASIC_LDAP_PROVIDER} dello security XML:
 * V1 era mutuamente esclusivo con {@code BASIC_GOVPAY_PROVIDER} (operatore
 * sceglieva uno o l'altro). V2 chain unica permette la coesistenza: questo
 * filter viene posizionato prima di {@code BasicAuthenticationFilter}. Se
 * LDAP autentica → context settato, marca {@link AuthType#LDAP}. Se LDAP
 * fallisce → context pulito, {@code BasicAuthenticationFilter} di Spring
 * fa il fallback verso il provider DAO (se {@code govpay.auth.basic.enabled}).
 *
 * <p>Niente self-stamping su fallimento: il filter passa "trasparente"
 * lasciando i filter successivi tentare.
 */
public class LdapAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(LdapAuthenticationFilter.class);

    private final BasicAuthenticationConverter converter = new BasicAuthenticationConverter();
    private final AuthenticationManager authenticationManager;
    private final AuthenticationDetailsContributor detailsContributor;

    public LdapAuthenticationFilter(AuthenticationManager authenticationManager,
                                    AuthenticationDetailsContributor detailsContributor) {
        this.authenticationManager = Objects.requireNonNull(authenticationManager, "authenticationManager");
        this.detailsContributor = Objects.requireNonNull(detailsContributor, "detailsContributor");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        UsernamePasswordAuthenticationToken authRequest;
        try {
            authRequest = converter.convert(request);
        } catch (Exception ex) {
            // Header malformato: lascia decidere al BasicAuthenticationFilter.
            chain.doFilter(request, response);
            return;
        }
        if (authRequest == null) {
            chain.doFilter(request, response);
            return;
        }
        authRequest.setDetails(detailsContributor.buildDetails(request, AuthType.LDAP));
        try {
            Authentication authResult = authenticationManager.authenticate(authRequest);
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authResult);
            SecurityContextHolder.setContext(context);
            request.setAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE, AuthType.LDAP);
        } catch (UsernameNotFoundException ex) {
            // Utenza non risolvibile localmente dopo LDAP-bind ok → fallisce esplicitamente.
            log.debug("LDAP bind ok ma utenza non risolvibile localmente per principal {}",
                    authRequest.getName(), ex);
            SecurityContextHolder.clearContext();
        } catch (AuthenticationException ex) {
            // Bind LDAP fallito: lascia il fallback al BasicAuthenticationFilter (DAO).
            log.debug("LDAP bind fallito per principal {}: {}",
                    authRequest.getName(), ex.getMessage());
            SecurityContextHolder.clearContext();
        }
        chain.doFilter(request, response);
    }
}
