package it.govpay.common.auth.spi;

/**
 * SPI fornita dal consumer della libreria. Mappa un {@code principal} (e il
 * tipo di autenticazione applicato) sul corrispondente {@link AuthenticatedSubject}.
 *
 * <p>La libreria common-auth non sa come il consumer persiste le utenze: ogni
 * consumer (govpay-console-api, govpay-portal-api, futuri WAR V2) implementa
 * un singolo {@code @Component} di questo tipo che interroga il proprio
 * data layer (JPA, LDAP, in-memory, ...).
 *
 * <p>L'implementazione deve essere thread-safe: viene invocata da Spring
 * Security una volta per request.
 *
 * <p>Restituisce {@code null} se il principal non e' noto: la libreria mappa
 * questo caso su {@code UsernameNotFoundException} (Spring Security 401).
 */
@FunctionalInterface
public interface GovpayPrincipalLoader {

    /**
     * @param principal identificativo dell'utenza (es. username Basic, CN cert SSL,
     *                  subject SPID, ...). Mai {@code null}.
     * @param authType  tipo di autenticazione che la chain ha applicato.
     *                  Permette al consumer di differenziare il lookup
     *                  (es. SSL legge dal campo {@code subject} invece che
     *                  {@code principal}) cosi' come V1 differenziava via
     *                  property {@code authType} sul bean DAO.
     * @return i dati dell'utenza autenticabile, oppure {@code null} se non
     *         esiste un'utenza con quel principal.
     */
    AuthenticatedSubject load(String principal, AuthType authType);
}
