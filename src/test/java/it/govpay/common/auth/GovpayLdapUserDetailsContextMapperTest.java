package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.AuthenticatedSubject;
import it.govpay.common.auth.spi.GovpayPrincipalLoader;

class GovpayLdapUserDetailsContextMapperTest {

    @Test
    void mergesLdapAndLocalAuthoritiesAndUsesLocalPrincipal() {
        GovpayPrincipalLoader loader = (principal, authType) -> {
            assertThat(authType).isEqualTo(AuthType.LDAP);
            return new AuthenticatedSubject("alice", null, true, List.of("amministratore", "operatore"));
        };
        GovpayLdapUserDetailsContextMapper mapper = new GovpayLdapUserDetailsContextMapper(loader, "ROLE_", true);

        UserDetails details = mapper.mapUserFromContext(
                /* ctx */ org.mockito.Mockito.mock(DirContextOperations.class),
                "alice",
                List.<GrantedAuthority>of(new SimpleGrantedAuthority("ROLE_LDAP_USER")));

        assertThat(details.getUsername()).isEqualTo("alice");
        assertThat(details.getPassword()).isEmpty();
        assertThat(details.isEnabled()).isTrue();
        assertThat(details.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_LDAP_USER", "ROLE_AMMINISTRATORE", "ROLE_OPERATORE");
    }

    @Test
    void throwsWhenPrincipalNotFoundLocally() {
        GovpayPrincipalLoader loader = (principal, authType) -> null;
        GovpayLdapUserDetailsContextMapper mapper = new GovpayLdapUserDetailsContextMapper(loader, "ROLE_", true);

        assertThatThrownBy(() -> mapper.mapUserFromContext(
                org.mockito.Mockito.mock(DirContextOperations.class), "ghost", List.of()))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("ghost");
    }

    @Test
    void mapUserToContextIsUnsupported() {
        GovpayLdapUserDetailsContextMapper mapper = new GovpayLdapUserDetailsContextMapper(
                (p, t) -> null, "ROLE_", true);
        assertThatThrownBy(() -> mapper.mapUserToContext(
                org.mockito.Mockito.mock(UserDetails.class),
                org.mockito.Mockito.mock(org.springframework.ldap.core.DirContextAdapter.class)))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}
