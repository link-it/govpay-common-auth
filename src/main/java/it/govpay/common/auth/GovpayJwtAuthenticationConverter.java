package it.govpay.common.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.AuthenticatedSubject;
import it.govpay.common.auth.spi.GovpayPrincipalLoader;

/**
 * Converte un {@link Jwt} validato in un {@link JwtAuthenticationToken}
 * pronto da mettere nel SecurityContext.
 *
 * <p>Estrae il principal dal claim configurato (recupera le authority "intrinseche"
 * del JWT via {@link JwtGrantedAuthoritiesConverter} e risolve l'utenza locale via
 * SPI {@link GovpayPrincipalLoader} con {@link AuthType#OAUTH2}; le authority
 * locali vengono unite a quelle estratte dal token. Il principal del token
 * finale e' il valore del claim.
 *
 * <p>{@code Utenza}/{@code Applicazione}/{@code Operatore} sono accessibili al
 * consumer via il proprio data layer (per principal noto) o via
 * {@link it.govpay.common.auth.spi.AuthenticationDetailsContributor}.
 */
public class GovpayJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private static final Logger log = LoggerFactory.getLogger(GovpayJwtAuthenticationConverter.class);
    private static final String ROLE_PREFIX = "ROLE_";

    private final GovpayPrincipalLoader loader;
    private final String principalClaimName;
    private final JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();

    public GovpayJwtAuthenticationConverter(GovpayPrincipalLoader loader, String principalClaimName) {
        this.loader = Objects.requireNonNull(loader, "loader");
        this.principalClaimName = (principalClaimName == null || principalClaimName.isBlank())
                ? "sub" : principalClaimName;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> jwtAuthorities = authoritiesConverter.convert(jwt);

        // supporto CSV per fallback claim name (es. "preferred_username,sub")
        String principalValue = null;
        for (String claimName : principalClaimName.split(",")) {
            principalValue = jwt.getClaimAsString(claimName.trim());
            if (principalValue != null) {
                log.debug("OAUTH2: principal '{}' estratto dal claim '{}'", principalValue, claimName.trim());
                break;
            }
        }
        if (principalValue == null) {
            throw new UsernameNotFoundException(
                    "Nessun claim valido per il principal tra: " + principalClaimName);
        }

        AuthenticatedSubject subject = loader.load(principalValue, AuthType.OAUTH2);
        if (subject == null) {
            throw new UsernameNotFoundException("Utenza OAUTH2 non trovata localmente: " + principalValue);
        }

        List<GrantedAuthority> merged = new ArrayList<>();
        if (jwtAuthorities != null) {
            merged.addAll(jwtAuthorities);
        }
        for (String role : subject.grantedRoles()) {
            String name = role.startsWith(ROLE_PREFIX) ? role : ROLE_PREFIX + role;
            merged.add(new SimpleGrantedAuthority(name));
        }

        return new JwtAuthenticationToken(jwt, merged, subject.principal());
    }
}
