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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.time.Instant;

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
    void stampsOauth2WhenAuthenticatedWithJwtAuthenticationToken() throws Exception {
        Jwt jwt = Jwt.withTokenValue("token-value")
                .header("alg", "RS256")
                .claim("sub", "alice")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
        SecurityContextHolder.getContext().setAuthentication(
                new JwtAuthenticationToken(jwt, List.of(new SimpleGrantedAuthority("ROLE_USER")), "alice"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer token-value");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(request.getAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE))
                .as("BearerTokenAuthenticationFilter non self-stamps: deve essere il filter "
                        + "a riconoscere JwtAuthenticationToken e marcare OAUTH2")
                .isEqualTo(AuthType.OAUTH2);
    }

    @Test
    void stampsOauth2WhenAuthorizationHeaderIsBearer() throws Exception {
        // Fallback: token Bearer custom (non-JWT). Spring autentica via altro
        // meccanismo che produce un Authentication generico; il cue header
        // Bearer e' sufficiente per marcare OAUTH2.
        authenticate("alice");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer custom-opaque-token");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        assertThat(request.getAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE))
                .isEqualTo(AuthType.OAUTH2);
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
