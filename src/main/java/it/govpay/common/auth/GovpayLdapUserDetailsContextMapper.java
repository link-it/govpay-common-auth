package it.govpay.common.auth;

import java.util.Collection;
import java.util.Objects;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.userdetails.UserDetailsContextMapper;

import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.AuthenticatedSubject;
import it.govpay.common.auth.spi.GovpayPrincipalLoader;

/**
 * Mapper invocato da {@code LdapAuthenticationProvider} di Spring Security
 * dopo che il bind LDAP e' riuscito. Per ogni utente autenticato via LDAP:
 * <ol>
 *   <li>verifica con la SPI {@link GovpayPrincipalLoader} che esista
 *       un'utenza corrispondente nel data layer del consumer (passando
 *       {@link AuthType#LDAP});</li>
 *   <li>combina le authority ricevute dal directory LDAP con quelle gia'
 *       risolte localmente (CSV {@code ruoli} dell'utenza), normalizzando
 *       il prefisso {@code ROLE_};</li>
 *   <li>ritorna uno Spring Security {@link UserDetails} senza esporre la
 *       password (verifica gia' avvenuta lato LDAP).</li>
 * </ol>
 *
 * <p>La responsabilita' di mappare il principal LDAP all'utenza locale e'
 * demandata al consumer tramite SPI.
 */
public class GovpayLdapUserDetailsContextMapper implements UserDetailsContextMapper {

    private static final String ROLE_PREFIX = "ROLE_";

    private final GovpayPrincipalLoader loader;
    private final String rolePrefix;
    private final boolean convertToUpperCase;

    public GovpayLdapUserDetailsContextMapper(GovpayPrincipalLoader loader,
                                              String rolePrefix,
                                              boolean convertToUpperCase) {
        this.loader = Objects.requireNonNull(loader, "loader");
        this.rolePrefix = rolePrefix == null ? ROLE_PREFIX : rolePrefix;
        this.convertToUpperCase = convertToUpperCase;
    }

    @Override
    public UserDetails mapUserFromContext(DirContextOperations ctx,
                                          String username,
                                          Collection<? extends GrantedAuthority> ldapAuthorities) {
        AuthenticatedSubject subject = loader.load(username, AuthType.LDAP);
        if (subject == null) {
            throw new UsernameNotFoundException("Utenza LDAP non trovata localmente: " + username);
        }

        var localAuthorities = subject.grantedRoles().stream()
                .map(this::normalizeRole)
                .map(SimpleGrantedAuthority::new)
                .map(GrantedAuthority.class::cast)
                .toList();

        return User.builder()
                .username(subject.principal())
                .password("")
                .authorities(java.util.stream.Stream.concat(
                        ldapAuthorities.stream(),
                        localAuthorities.stream()).toList())
                .disabled(!subject.enabled())
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .build();
    }

    @Override
    public void mapUserToContext(UserDetails user, DirContextAdapter ctx) {
        throw new UnsupportedOperationException(
                "GovpayLdapUserDetailsContextMapper supporta solo lettura dal context LDAP.");
    }

    private String normalizeRole(String role) {
        String r = role == null ? "" : role.trim();
        if (convertToUpperCase) {
            r = r.toUpperCase();
        }
        return r.startsWith(rolePrefix) ? r : rolePrefix + r;
    }
}
