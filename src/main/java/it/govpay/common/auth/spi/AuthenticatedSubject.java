package it.govpay.common.auth.spi;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

/**
 * Dati minimi che la libreria common-auth riceve dal consumer per costruire
 * lo {@link org.springframework.security.core.userdetails.UserDetails} di
 * Spring Security.
 *
 * <p>Restituito da {@link GovpayPrincipalLoader#load(String, AuthType)}. La
 * libreria non sa nulla del modello dominio del consumer (entity, ACL,
 * domini, tipi pendenza): vede solo principal + password hash + abilitato +
 * ruoli granted.
 *
 * @param principal     identificativo dell'utenza (es. username o subject del cert)
 * @param passwordHash  hash della password (nullo per modi senza password:
 *                      SSL, SPID, HEADER, ...). Quando presente deve essere
 *                      verificabile da
 *                      {@link it.govpay.common.auth.GovpayPasswordEncoder}.
 * @param enabled       {@code false} = utenza disabilitata, l'auth fallisce
 *                      con {@link FailureReason#DISABLED}
 * @param grantedRoles  nomi dei ruoli da convertire in {@code SimpleGrantedAuthority}.
 *                      Il prefisso {@code ROLE_} viene aggiunto dalla libreria
 *                      se mancante.
 */
public record AuthenticatedSubject(
        String principal,
        String passwordHash,
        boolean enabled,
        Collection<String> grantedRoles) {

    public AuthenticatedSubject {
        Objects.requireNonNull(principal, "principal");
        grantedRoles = grantedRoles == null ? List.of() : List.copyOf(grantedRoles);
    }
}
