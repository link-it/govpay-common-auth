package it.govpay.common.auth;

import java.util.Objects;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.AuthenticatedSubject;
import it.govpay.common.auth.spi.GovpayPrincipalLoader;

/**
 * Adapter Spring Security &harr; SPI {@link GovpayPrincipalLoader}.
 *
 * <p>Un'istanza per ciascun {@link AuthType} attivo: la chain corrispondente
 * la inietta in un suo {@link org.springframework.security.authentication.dao.DaoAuthenticationProvider}
 * (per metodi password-based) o in un
 * {@link org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper}
 * (per metodi pre-auth).
 */
public class GovpayUserDetailsServiceAdapter implements UserDetailsService {

    private static final String ROLE_PREFIX = "ROLE_";

    private final GovpayPrincipalLoader loader;
    private final AuthType authType;

    public GovpayUserDetailsServiceAdapter(GovpayPrincipalLoader loader, AuthType authType) {
        this.loader = Objects.requireNonNull(loader, "loader");
        this.authType = Objects.requireNonNull(authType, "authType");
    }

    @Override
    public UserDetails loadUserByUsername(String principal) {
        AuthenticatedSubject subject = loader.load(principal, authType);
        if (subject == null) {
            throw new UsernameNotFoundException("Principal non trovato: " + principal);
        }
        return User.builder()
                .username(subject.principal())
                .password(subject.passwordHash() != null ? subject.passwordHash() : "")
                .authorities(subject.grantedRoles().stream()
                        .map(GovpayUserDetailsServiceAdapter::asAuthority)
                        .toList())
                .disabled(!subject.enabled())
                .accountExpired(false)
                .accountLocked(false)
                .credentialsExpired(false)
                .build();
    }

    public AuthType getAuthType() {
        return authType;
    }

    private static SimpleGrantedAuthority asAuthority(String role) {
        String trimmed = role.trim();
        String name = trimmed.startsWith(ROLE_PREFIX) ? trimmed : ROLE_PREFIX + trimmed;
        return new SimpleGrantedAuthority(name);
    }
}
