package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import it.govpay.common.auth.spi.AuthType;

class AuthTypeStampingFilterTest {

    private final AuthTypeStampingFilter filter = new AuthTypeStampingFilter();

    @BeforeEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void stampsBasicWhenAuthenticatedWithBasicHeader() throws Exception {
        authenticate("alice");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic YWxpY2U6cGFzc3dvcmQ=");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        filter.doFilter(request, response, chain);

        assertThat(request.getAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE))
                .isEqualTo(AuthType.BASIC);
        assertThat(AuthTypeAccessor.current(request)).isEqualTo(AuthType.BASIC);
    }

    @Test
    void doesNotStampWhenAuthorizationHeaderMissing() throws Exception {
        authenticate("alice");
        MockHttpServletRequest request = new MockHttpServletRequest();

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(request.getAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE)).isNull();
        assertThat(AuthTypeAccessor.current(request)).isNull();
    }

    @Test
    void doesNotStampWhenAuthorizationHeaderIsNotBasic() throws Exception {
        authenticate("alice");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer abc.def.ghi");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(request.getAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE)).isNull();
    }

    @Test
    void doesNotStampWhenContextEmpty() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic YWxpY2U6cGFzc3dvcmQ=");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(request.getAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE)).isNull();
    }

    @Test
    void doesNotStampForAnonymousAuthentication() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                new AnonymousAuthenticationToken("key", "anonymousUser",
                        List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Basic YWxpY2U6cGFzc3dvcmQ=");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(request.getAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE)).isNull();
    }

    @Test
    void caseInsensitiveBasicPrefix() throws Exception {
        authenticate("alice");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "bAsIc YWxpY2U6cGFzc3dvcmQ=");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(request.getAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE))
                .isEqualTo(AuthType.BASIC);
    }

    private static void authenticate(String principal) {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(principal, "n/a",
                        List.of(new SimpleGrantedAuthority("ROLE_USER"))));
    }
}
