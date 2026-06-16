package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;

class SessionPreAuthenticationFilterTest {

    @Test
    void constructorRejectsBlankAttributeName() {
        assertThatThrownBy(() -> new SessionPreAuthenticationFilter(""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void returnsNullWhenSessionMissing() {
        SessionPreAuthenticationFilter filter = new SessionPreAuthenticationFilter("GP_PRINCIPAL");
        assertThat(filter.getPreAuthenticatedPrincipal(new MockHttpServletRequest())).isNull();
    }

    @Test
    void returnsNullWhenAttributeAbsent() {
        SessionPreAuthenticationFilter filter = new SessionPreAuthenticationFilter("GP_PRINCIPAL");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setSession(new MockHttpSession());

        assertThat(filter.getPreAuthenticatedPrincipal(request)).isNull();
    }

    @Test
    void returnsPrincipalFromSessionAttribute() {
        SessionPreAuthenticationFilter filter = new SessionPreAuthenticationFilter("GP_PRINCIPAL");
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        session.setAttribute("GP_PRINCIPAL", "alice");
        request.setSession(session);

        assertThat(filter.getPreAuthenticatedPrincipal(request)).isEqualTo("alice");
    }

    @Test
    void getPreAuthenticatedCredentialsAlwaysNA() {
        SessionPreAuthenticationFilter filter = new SessionPreAuthenticationFilter("GP_PRINCIPAL");
        assertThat(filter.getPreAuthenticatedCredentials(new MockHttpServletRequest())).isEqualTo("N/A");
    }
}
