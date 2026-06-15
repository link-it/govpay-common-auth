package it.govpay.common.auth;

import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Filter pre-auth per il caso in cui un reverse proxy / API gateway termina
 * la mTLS e propaga il subject DN del certificato client via header HTTP.
 *
 * <p>Differenza con V1 ({@code SSLHeaderPreAuthFilter}): V1 supportava
 * encoding base64/URL e replace caratteri sul cert PEM inoltrato in header,
 * con parsing X.509 interno. Qui assumiamo che l'header porti gia' il
 * subject DN pronto (configurazione tipica per nginx: {@code $ssl_client_s_dn}).
 * Gateway che inoltrano il cert raw devono pre-decodificarlo a monte, oppure
 * registrare un loro {@code @Component} con questo {@code AuthType} per
 * gestire l'encoding specifico.
 */
public class SslHeaderPreAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

    private final String principalHeaderName;

    public SslHeaderPreAuthenticationFilter(String principalHeaderName) {
        if (principalHeaderName == null || principalHeaderName.isBlank()) {
            throw new IllegalArgumentException("principalHeaderName must not be blank");
        }
        this.principalHeaderName = principalHeaderName;
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        return request.getHeader(principalHeaderName);
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "N/A";
    }
}
