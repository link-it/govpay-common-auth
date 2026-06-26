package it.govpay.common.auth.spi;

/**
 * Tipo di autenticazione applicato a una request.
 *
 * <p>I codici corrispondono ai valori {@code authType} usati storicamente da
 * GovPay. Sono stabili verso l'esterno: vengono esposti come stringhe in
 * {@code Profilo.autenticazione} e in {@code GET /auth/methods}, ed
 * eventuali consumer terzi possono fare matching su di essi.
 */
public enum AuthType {
    BASIC,
    LDAP,
    FORM,
    SSL,
    SSL_HEADER,
    HEADER,
    API_KEY,
    SPID,
    SESSION,
    OAUTH2,
    PUBLIC
}
