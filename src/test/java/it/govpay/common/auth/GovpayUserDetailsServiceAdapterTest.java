package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.AuthenticatedSubject;
import it.govpay.common.auth.spi.GovpayPrincipalLoader;

class GovpayUserDetailsServiceAdapterTest {

    @Test
    void loadReturnsUserDetailsForKnownPrincipal() {
        GovpayPrincipalLoader loader = (principal, authType) -> new AuthenticatedSubject(
                "alice", "$6$abc$hash", true, List.of("AMMINISTRATORE", "OPERATORE"));
        var adapter = new GovpayUserDetailsServiceAdapter(loader, AuthType.BASIC);

        UserDetails details = adapter.loadUserByUsername("alice");

        assertThat(details.getUsername()).isEqualTo("alice");
        assertThat(details.getPassword()).isEqualTo("$6$abc$hash");
        assertThat(details.isEnabled()).isTrue();
        assertThat(details.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_AMMINISTRATORE", "ROLE_OPERATORE");
    }

    @Test
    void loadThrowsWhenPrincipalUnknown() {
        GovpayPrincipalLoader loader = (principal, authType) -> null;
        var adapter = new GovpayUserDetailsServiceAdapter(loader, AuthType.BASIC);

        assertThatThrownBy(() -> adapter.loadUserByUsername("bob"))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessageContaining("bob");
    }

    @Test
    void loadMarksDisabledUserAccordingly() {
        GovpayPrincipalLoader loader = (principal, authType) -> new AuthenticatedSubject(
                "alice", "$6$abc$hash", false, List.of());
        var adapter = new GovpayUserDetailsServiceAdapter(loader, AuthType.BASIC);

        UserDetails details = adapter.loadUserByUsername("alice");

        assertThat(details.isEnabled()).isFalse();
    }

    @Test
    void loadKeepsRolePrefixWhenAlreadyPresent() {
        GovpayPrincipalLoader loader = (principal, authType) -> new AuthenticatedSubject(
                "alice", null, true, List.of("ROLE_X", "Y"));
        var adapter = new GovpayUserDetailsServiceAdapter(loader, AuthType.SSL);

        UserDetails details = adapter.loadUserByUsername("alice");

        assertThat(details.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("ROLE_X", "ROLE_Y");
    }

    @Test
    void loadHandlesNullPasswordForPreAuthSubjects() {
        GovpayPrincipalLoader loader = (principal, authType) -> new AuthenticatedSubject(
                "cert-cn", null, true, List.of());
        var adapter = new GovpayUserDetailsServiceAdapter(loader, AuthType.SSL);

        UserDetails details = adapter.loadUserByUsername("cert-cn");

        assertThat(details.getPassword()).isEmpty();
        assertThat(adapter.getAuthType()).isEqualTo(AuthType.SSL);
    }

    @Test
    void loadPropagatesAuthTypeToLoader() {
        AuthType[] captured = new AuthType[1];
        GovpayPrincipalLoader loader = (principal, authType) -> {
            captured[0] = authType;
            return new AuthenticatedSubject(principal, "$6$x$y", true, List.of());
        };
        var adapter = new GovpayUserDetailsServiceAdapter(loader, AuthType.FORM);

        adapter.loadUserByUsername("alice");

        assertThat(captured[0]).isEqualTo(AuthType.FORM);
    }
}
