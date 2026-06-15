package it.govpay.common.auth.spi;

import jakarta.servlet.http.HttpServletRequest;

/**
 * SPI per popolare il campo {@code details} dell'{@link org.springframework.security.core.Authentication}
 * con informazioni custom (header tracciati, attributi SPID, IP del chiamante,
 * eccetera). Replica concettualmente il pattern V1
 * {@code HeaderAuthenticationDetailsSource} + {@code GovpayWebAuthenticationDetails}
 * generalizzandolo in SPI: il consumer registra un {@code @Component} di
 * questo tipo e la libreria lo collega ai filter dei metodi che lo supportano.
 *
 * <p>Allineato a V1, la contribution di details e' rilevante per i metodi
 * pre-auth (HEADER, SSL_HEADER, API_KEY, SPID, SESSION). Per i metodi BASIC,
 * FORM e SSL (X.509 nativo), V1 usa il default Spring
 * ({@code WebAuthenticationDetails}); V2 mantiene lo stesso comportamento.
 *
 * <p>Se il consumer non registra una propria implementazione, la libreria
 * espone un {@link it.govpay.common.auth.DefaultAuthenticationDetailsContributor}
 * che delega a {@code WebAuthenticationDetailsSource} di Spring.
 */
public interface AuthenticationDetailsContributor {

    /**
     * @param request  la request HTTP corrente
     * @param authType il tipo di autenticazione applicato dal filter che ha
     *                 vinto, utile al consumer per capturare attributi
     *                 specifici (es. header SPID solo per AuthType.SPID)
     * @return oggetto da attaccare a {@code Authentication.setDetails(...)}.
     *         Mai {@code null} (in caso di nessuna details, ritornare
     *         comunque un {@code WebAuthenticationDetails} di default).
     */
    Object buildDetails(HttpServletRequest request, AuthType authType);
}
