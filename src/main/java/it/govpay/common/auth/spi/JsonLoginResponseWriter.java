package it.govpay.common.auth.spi;

import java.io.IOException;

import org.springframework.security.core.Authentication;

import jakarta.servlet.http.HttpServletResponse;

/**
 * SPI per personalizzare il body della risposta di {@code POST /auth/login}
 * in caso di successo.
 *
 * <p>La libreria common-auth non conosce il modello applicativo del consumer
 * (es. {@code Profilo} di govpay-console-api): demanda al consumer la
 * scrittura del body. Il consumer registra un proprio {@code @Component}
 * che implementa questa SPI per ritornare al frontend, sulla stessa
 * response del login, il payload utile (tipicamente {@code Profilo} +
 * ACL/domini/tipi pendenza).
 *
 * <p>Se il consumer non registra niente, common-auth espone un'implementazione
 * default minimale {@code DefaultJsonLoginResponseWriter} che scrive
 * {@code {"principal":"...","autenticazione":"FORM"}}.
 */
public interface JsonLoginResponseWriter {

    /**
     * Scrive sul {@link HttpServletResponse} il body della risposta di login
     * riuscito. {@code Content-Type} di solito {@code application/json}, ma
     * l'implementatore puo' impostarne uno diverso.
     *
     * @param response       la response HTTP, gia' con status 200 ma senza body
     * @param authentication l'{@link Authentication} appena prodotto dal manager
     * @throws IOException se la scrittura della response fallisce
     */
    void writeSuccessBody(HttpServletResponse response, Authentication authentication) throws IOException;
}
