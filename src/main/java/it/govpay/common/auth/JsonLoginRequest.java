package it.govpay.common.auth;

/**
 * Schema del body JSON accettato da {@code POST /auth/login}.
 *
 * <p>Volutamente minimale: solo username e password. Eventuali campi aggiuntivi
 * (es. MFA token) verranno gestiti da SPI dedicate, non da estensioni di
 * questo record.
 */
public record JsonLoginRequest(String username, String password) {
}
