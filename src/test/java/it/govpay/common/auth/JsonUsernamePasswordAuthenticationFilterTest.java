package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import it.govpay.common.auth.spi.AuthEventListener;
import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.AuthenticationDetailsContributor;
import it.govpay.common.auth.spi.FailureReason;
import it.govpay.common.auth.spi.JsonLoginResponseWriter;

/**
 * Verifica focalizzata che il filter rispetti il contratto verso
 * {@link AuthEventListener}, in particolare che propaghi correttamente
 * lo {@code attemptedPrincipal} estratto dal body JSON a
 * {@link AuthEventListener#onLoginFailed} quando il manager solleva
 * eccezione.
 *
 * <p>Bug originale: {@code attemptAuthentication} parsava lo username
 * ma non lo stampava su request attribute, quindi
 * {@code unsuccessfulAuthentication} passava sempre {@code null}; il
 * consumer audit (es. console-api) di conseguenza saltava la riga
 * {@code PROFILO_LOGIN_FAILED}.
 */
class JsonUsernamePasswordAuthenticationFilterTest {

    private ObjectMapper objectMapper;
    private JsonLoginResponseWriter responseWriter;
    private AuthEventListener eventListener;
    private LoginRateLimiter rateLimiter;
    private AuthenticationDetailsContributor detailsContributor;
    private AuthenticationManager authenticationManager;
    private JsonUsernamePasswordAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        objectMapper = JsonMapper.builder().build();
        responseWriter = mock(JsonLoginResponseWriter.class);
        eventListener = mock(AuthEventListener.class);
        rateLimiter = mock(LoginRateLimiter.class);
        detailsContributor = mock(AuthenticationDetailsContributor.class);
        authenticationManager = mock(AuthenticationManager.class);

        when(rateLimiter.tryAcquire(anyString())).thenReturn(true);
        when(detailsContributor.buildDetails(any(), any())).thenReturn(null);

        filter = new JsonUsernamePasswordAuthenticationFilter(
                "/auth/login", objectMapper, responseWriter, eventListener, rateLimiter, detailsContributor);
        filter.setAuthenticationManager(authenticationManager);
        filter.setSecurityContextRepository(new HttpSessionSecurityContextRepository());
    }

    @Test
    void badCredentialsPropagatesAttemptedPrincipalToListener() throws Exception {
        when(authenticationManager.authenticate(any()))
                .thenThrow(new BadCredentialsException("creds non valide"));

        MockHttpServletRequest request = postLogin("alice", "wrong");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        verify(eventListener).onLoginFailed(
                eq("alice"), eq(AuthType.FORM), eq(FailureReason.BAD_CREDENTIALS), eq(request));
        verify(rateLimiter).recordFailure(anyString());
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).isEqualTo("application/problem+json");
    }

    @Test
    void disabledUtenzaPropagatesAttemptedPrincipalToListener() throws Exception {
        when(authenticationManager.authenticate(any()))
                .thenThrow(new DisabledException("utenza disabilitata"));

        MockHttpServletRequest request = postLogin("bob", "secret");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        verify(eventListener).onLoginFailed(
                eq("bob"), eq(AuthType.FORM), eq(FailureReason.DISABLED), eq(request));
        assertThat(response.getStatus()).isEqualTo(401);
    }

    @Test
    void successfulAuthenticationInvokesListenerWithPrincipal() throws Exception {
        Authentication authenticated = UsernamePasswordAuthenticationToken.authenticated(
                "carol", "secret", java.util.List.of());
        when(authenticationManager.authenticate(any())).thenReturn(authenticated);

        MockHttpServletRequest request = postLogin("carol", "secret");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        verify(eventListener).onLoginSuccess(eq("carol"), eq(AuthType.FORM), eq(request));
        verify(rateLimiter).reset(anyString());
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void rateLimitedRequestNotifiesListenerWithAttemptedPrincipal() throws Exception {
        when(rateLimiter.tryAcquire(anyString())).thenReturn(false);

        MockHttpServletRequest request = postLogin("alice", "wrong");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        // RATE_LIMITED arriva DOPO il parsing del body: il listener riceve lo
        // username tentato (non null), cosi' il consumer puo' tracciare
        // PROFILO_LOGIN_FAILED motivo=RATE_LIMITED per principal noti (vedi
        // contratto openapi.yaml /auth/login response 429).
        verify(eventListener).onLoginFailed(
                eq("alice"), eq(AuthType.FORM), eq(FailureReason.RATE_LIMITED), eq(request));
        verifyNoInteractions(authenticationManager);
        assertThat(response.getStatus()).isEqualTo(429);
    }

    @Test
    void rateLimitedRequestWithMalformedBodyNotifiesWithNullPrincipal() throws Exception {
        // Body malformato → BAD_CREDENTIALS notificato con principal=null
        // (non possiamo estrarre username); il rate-limit non viene neppure
        // valutato perche' il body parsing fallisce prima. Documenta che il
        // 400 ha priorita' sul 429 quando il body non e' parsabile.
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/login");
        request.setServletPath("/auth/login");
        request.setRequestURI("/auth/login");
        request.setContentType("application/json");
        request.setContent("not-json".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        request.setRemoteAddr("127.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        verify(eventListener).onLoginFailed(
                eq(null), eq(AuthType.FORM), eq(FailureReason.BAD_CREDENTIALS), eq(request));
        assertThat(response.getStatus()).isEqualTo(400);
    }

    private MockHttpServletRequest postLogin(String username, String password) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/login");
        request.setServletPath("/auth/login");
        request.setRequestURI("/auth/login");
        request.setContentType("application/json");
        String body = "{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
        request.setContent(body.getBytes(StandardCharsets.UTF_8));
        request.setRemoteAddr("127.0.0.1");
        return request;
    }
}
