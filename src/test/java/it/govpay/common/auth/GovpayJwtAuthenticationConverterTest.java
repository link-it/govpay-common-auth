package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.Jwt;

import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.AuthenticatedSubject;

class GovpayJwtAuthenticationConverterTest {

    private static Jwt jwt(String sub) {
        return Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .claim("sub", sub)
                .claim("scope", "read")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
    }

    @Test
    void enabledSubjectIsAuthenticatedWithMergedAuthorities() {
        GovpayJwtAuthenticationConverter converter = new GovpayJwtAuthenticationConverter(
                (principal, authType) -> {
                    assertThat(authType).isEqualTo(AuthType.OAUTH2);
                    return new AuthenticatedSubject(principal, null, true, List.of("OPERATORE"));
                }, "sub");

        AbstractAuthenticationToken token = converter.convert(jwt("alice"));

        assertThat(token.getName()).isEqualTo("alice");
        assertThat(token.getAuthorities()).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("SCOPE_read", "ROLE_OPERATORE");
    }

    @Test
    void disabledSubjectIsRejected() {
        GovpayJwtAuthenticationConverter converter = new GovpayJwtAuthenticationConverter(
                (principal, authType) -> new AuthenticatedSubject(principal, null, false, List.of("OPERATORE")),
                "sub");

        assertThatThrownBy(() -> converter.convert(jwt("alice")))
                .isInstanceOf(DisabledException.class);
    }

    @Test
    void unknownSubjectIsRejected() {
        GovpayJwtAuthenticationConverter converter = new GovpayJwtAuthenticationConverter(
                (principal, authType) -> null, "sub");

        assertThatThrownBy(() -> converter.convert(jwt("alice")))
                .isInstanceOf(UsernameNotFoundException.class);
    }
}
