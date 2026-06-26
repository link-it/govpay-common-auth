package it.govpay.common.auth;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import it.govpay.common.auth.spi.AuthType;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter pre-auth per il caso in cui un Identity Provider SPID (esterno o
 * shibboleth-proxy) ha gia' autenticato l'utente upstream e propaga
 * l'identita' via header HTTP.
 *
 * <p>Legge il principal dall'header configurato; se il valore inizia con il
 * prefisso convenzionale {@code TINIT-} (Tipo Identificativo Naturale ITaliano),
 * strippa il prefisso per ottenere il codice fiscale puro.
 *
 * <p>Esempio: header valorizzato {@code TINIT-RSSMRA80A01H501Z} → principal
 * {@code RSSMRA80A01H501Z}.
 *
 * <p><b>Attributi SPID nel details</b>: Cattura di header SPID e' demandata
 * al consumer tramite {@link it.govpay.common.auth.spi.AuthenticationDetailsContributor}:
 * il consumer registra un proprio bean che ispeziona la request e ritorna
 * un details object con i campi che gli interessano.
 *
 * <p><b>CSRF su SPID</b>: Chain unica abilita CSRF condizionalmente (cookie sessione 
 * presente + no Authorization header). Dopo login SPID, le request successive
 * portano cookie sessione → CSRF richiesto. Il frontend SPID deve gestire
 * il token {@code X-XSRF-TOKEN} come per FORM.
 */
public class SpidPreAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

    private static final Logger log = LoggerFactory.getLogger(SpidPreAuthenticationFilter.class);

    private final String principalHeaderName;
    private final String tinitPrefix;

    public SpidPreAuthenticationFilter(String principalHeaderName, String tinitPrefix) {
        this.principalHeaderName = Objects.requireNonNull(principalHeaderName, "principalHeaderName");
        if (principalHeaderName.isBlank()) {
            throw new IllegalArgumentException("principalHeaderName must not be blank");
        }
        this.tinitPrefix = tinitPrefix == null ? "" : tinitPrefix;
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        String value = request.getHeader(principalHeaderName);
        if (value == null || value.isBlank()) {
            return null;
        }
        if (!tinitPrefix.isEmpty()) {
            int idx = value.indexOf(tinitPrefix);
            if (idx >= 0) {
                String cf = value.substring(idx + tinitPrefix.length());
                log.debug("SPID principal estratto dopo strip {} prefix: [{}]", tinitPrefix, cf);
                return cf;
            }
        }
        log.debug("SPID principal letto raw da header [{}]: [{}]", principalHeaderName, value);
        return value;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "N/A";
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            Authentication authResult) throws java.io.IOException, ServletException {
        super.successfulAuthentication(request, response, authResult);
        request.setAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE, AuthType.SPID);
        request.setAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE_PRINCIPAL, authResult.getName());
    }
}
