package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

class ApiKeyAuthenticationFilterTest {

    @BeforeEach
    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void doesNothingWhenHeadersAreMissing() throws Exception {
        AuthenticationManager manager = authentication -> {
            throw new IllegalStateException("manager non avrebbe dovuto essere chiamato");
        };
        ApiKeyAuthenticationFilter filter = new ApiKeyAuthenticationFilter(
                "X-Govpay-API-ID", "X-Govpay-API-Key", manager);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(chain.getRequest()).isSameAs(request);
    }

    @Test
    void authenticatesWhenBothHeadersArePresent() throws Exception {
        AuthenticationManager manager = authentication -> UsernamePasswordAuthenticationToken.authenticated(
                authentication.getName(), null,
                List.of(new SimpleGrantedAuthority("ROLE_APPLICAZIONE")));
        ApiKeyAuthenticationFilter filter = new ApiKeyAuthenticationFilter(
                "X-Govpay-API-ID", "X-Govpay-API-Key", manager);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Govpay-API-ID", "client-001");
        request.addHeader("X-Govpay-API-Key", "secret-key");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isNotNull();
        assertThat(auth.getName()).isEqualTo("client-001");
        assertThat(auth.isAuthenticated()).isTrue();
    }

    @Test
    void clearsContextOnAuthenticationFailure() throws Exception {
        AuthenticationManager manager = authentication -> {
            throw new BadCredentialsException("nope");
        };
        ApiKeyAuthenticationFilter filter = new ApiKeyAuthenticationFilter(
                "X-Govpay-API-ID", "X-Govpay-API-Key", manager);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Govpay-API-ID", "client-001");
        request.addHeader("X-Govpay-API-Key", "wrong-key");
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        // chain continua: l'eventuale 401 e' demandato all'entry point della chain.
        assertThat(chain.getRequest()).isSameAs(request);
    }
}
