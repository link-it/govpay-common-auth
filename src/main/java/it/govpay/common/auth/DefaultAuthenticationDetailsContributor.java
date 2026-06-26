package it.govpay.common.auth;

import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;

import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.AuthenticationDetailsContributor;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Default minimale di {@link AuthenticationDetailsContributor}: delega a
 * {@link WebAuthenticationDetailsSource} di Spring (lo stesso default usato
 * dai filter di Spring Security quando il filter non ha un
 * {@code AuthenticationDetailsSource} esplicito).
 *
 * <p>Sostituibile dal consumer registrando un proprio bean che implementa
 * {@link AuthenticationDetailsContributor}: utile per attaccare header
 * specifici, attributi SPID, info del proxy a monte, ecc.
 */
public class DefaultAuthenticationDetailsContributor implements AuthenticationDetailsContributor {

    private final WebAuthenticationDetailsSource delegate = new WebAuthenticationDetailsSource();

    @Override
    public Object buildDetails(HttpServletRequest request, AuthType authType) {
        return delegate.buildDetails(request);
    }
}
