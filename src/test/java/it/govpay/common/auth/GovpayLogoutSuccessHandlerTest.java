package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import it.govpay.common.auth.spi.AuthEventListener;
import it.govpay.common.auth.spi.AuthType;

import jakarta.servlet.http.HttpServletRequest;

class GovpayLogoutSuccessHandlerTest {

    @Test
    void emits204AndNotifiesListener() throws Exception {
        AtomicReference<String> capturedPrincipal = new AtomicReference<>();
        AuthEventListener listener = new AuthEventListener() {
            @Override
            public void onLogout(String principal, HttpServletRequest request) {
                capturedPrincipal.set(principal);
            }
        };
        GovpayLogoutSuccessHandler handler = new GovpayLogoutSuccessHandler(listener);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication auth = new UsernamePasswordAuthenticationToken(
                "alice", "n/a", List.of(new SimpleGrantedAuthority("ROLE_USER")));

        handler.onLogoutSuccess(request, response, auth);

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(capturedPrincipal.get()).isEqualTo("alice");
    }

    @Test
    void handlesNullAuthenticationGracefully() throws Exception {
        AtomicReference<String> capturedPrincipal = new AtomicReference<>("unset");
        AuthEventListener listener = new AuthEventListener() {
            @Override
            public void onLogout(String principal, HttpServletRequest request) {
                capturedPrincipal.set(principal);
            }
        };
        GovpayLogoutSuccessHandler handler = new GovpayLogoutSuccessHandler(listener);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onLogoutSuccess(new MockHttpServletRequest(), response, null);

        assertThat(response.getStatus()).isEqualTo(204);
        assertThat(capturedPrincipal.get()).isNull();
    }

    @Test
    void unusedImportForCoverage() {
        // AuthType import per coverage; non rilevante alla logica.
        assertThat(AuthType.FORM.name()).isEqualTo("FORM");
    }
}
