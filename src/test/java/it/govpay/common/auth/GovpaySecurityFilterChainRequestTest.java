package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;

import jakarta.servlet.Filter;
import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import it.govpay.common.auth.spi.AuthenticatedSubject;
import it.govpay.common.auth.spi.GovpayPrincipalLoader;

/**
 * Richieste reali attraverso la {@code springSecurityFilterChain} costruita
 * dalle auto-configurazioni.
 */
class GovpaySecurityFilterChainRequestTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withBean(ObjectMapper.class, () -> JsonMapper.builder().build())
            .withConfiguration(AutoConfigurations.of(
                    SecurityAutoConfiguration.class,
                    GovpayAuthAutoConfiguration.class,
                    GovpaySecurityFilterChainAutoConfiguration.class));

    private static MockHttpServletResponse perform(ApplicationContext context, MockHttpServletRequest request)
            throws Exception {
        Filter chain = context.getBean("springSecurityFilterChain", Filter.class);
        MockHttpServletResponse response = new MockHttpServletResponse();
        chain.doFilter(request, response, new MockFilterChain());
        return response;
    }

    @Test
    void sessionAndOauth2LogoutCoexist() {
        runner.withUserConfiguration(EnabledUserConfig.class)
                .withPropertyValues(
                        "govpay.auth.form.enabled=true",
                        "govpay.auth.oauth2.enabled=true",
                        "govpay.auth.oauth2.logout-uri=https://idp.example.com/logout",
                        "govpay.auth.oauth2.post-logout-redirect-uri=https://console.example.com/")
                .run(context -> {
                    MockHttpServletRequest formLogout = new MockHttpServletRequest("POST", "/auth/logout");
                    MockHttpSession session = new MockHttpSession();
                    formLogout.setSession(session);
                    MockHttpServletResponse formResponse = perform(context, formLogout);
                    assertThat(formResponse.getStatus()).isEqualTo(204);
                    assertThat(session.isInvalid()).isTrue();

                    MockHttpServletRequest oauthLogout = new MockHttpServletRequest("POST", "/auth/oauth2/logout");
                    MockHttpServletResponse oauthResponse = perform(context, oauthLogout);
                    assertThat(oauthResponse.getStatus()).isEqualTo(200);
                    assertThat(oauthResponse.getContentAsString())
                            .contains("https://idp.example.com/logout?post_logout_redirect_uri=");
                });
    }

    @Test
    void sessionLogoutWithoutOauth2() {
        runner.withUserConfiguration(EnabledUserConfig.class)
                .withPropertyValues("govpay.auth.form.enabled=true")
                .run(context -> {
                    MockHttpServletResponse response =
                            perform(context, new MockHttpServletRequest("POST", "/auth/logout"));
                    assertThat(response.getStatus()).isEqualTo(204);
                });
    }

    @Test
    void oauth2LogoutWithoutSessionMethods() {
        runner.withUserConfiguration(EnabledUserConfig.class)
                .withPropertyValues(
                        "govpay.auth.oauth2.enabled=true",
                        "govpay.auth.oauth2.logout-uri=https://idp.example.com/logout",
                        "govpay.auth.oauth2.post-logout-redirect-uri=https://console.example.com/")
                .run(context -> {
                    MockHttpServletResponse response =
                            perform(context, new MockHttpServletRequest("POST", "/auth/oauth2/logout"));
                    assertThat(response.getStatus()).isEqualTo(200);
                    MockHttpServletResponse sessionLogout =
                            perform(context, new MockHttpServletRequest("POST", "/auth/logout"));
                    assertThat(sessionLogout.getStatus()).isEqualTo(401);
                });
    }

    @Test
    void bearerTokenOfEnabledUserIsAccepted() {
        runner.withUserConfiguration(EnabledUserConfig.class)
                .withPropertyValues("govpay.auth.oauth2.enabled=true")
                .run(context -> {
                    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/risorsa");
                    request.addHeader("Authorization", "Bearer token");
                    assertThat(perform(context, request).getStatus()).isEqualTo(200);
                });
    }

    @Test
    void bearerTokenOfDisabledUserIsRejectedWith401() {
        runner.withUserConfiguration(DisabledUserConfig.class)
                .withPropertyValues("govpay.auth.oauth2.enabled=true")
                .run(context -> {
                    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/risorsa");
                    request.addHeader("Authorization", "Bearer token");
                    MockHttpServletResponse response = perform(context, request);
                    assertThat(response.getStatus()).isEqualTo(401);
                    assertThat(response.getContentType()).isEqualTo("application/problem+json");
                });
    }

    @Test
    void defaultEntryPointAnswersProblemJson() {
        runner.withUserConfiguration(EnabledUserConfig.class)
                .run(context -> {
                    MockHttpServletResponse response =
                            perform(context, new MockHttpServletRequest("GET", "/api/risorsa"));
                    assertThat(response.getStatus()).isEqualTo(401);
                    assertThat(response.getContentType()).isEqualTo("application/problem+json");
                });
    }

    @Test
    void customEntryPointIsUsedByTheChain() {
        runner.withUserConfiguration(EnabledUserConfig.class, CustomEntryPointConfig.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    MockHttpServletResponse response =
                            perform(context, new MockHttpServletRequest("GET", "/api/risorsa"));
                    assertThat(response.getStatus()).isEqualTo(CUSTOM_ENTRY_POINT_STATUS);
                });
    }

    @Test
    void customEntryPointIsUsedWithOauth2Enabled() {
        runner.withUserConfiguration(EnabledUserConfig.class, CustomEntryPointConfig.class)
                .withPropertyValues("govpay.auth.oauth2.enabled=true")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    MockHttpServletResponse response =
                            perform(context, new MockHttpServletRequest("GET", "/api/risorsa"));
                    assertThat(response.getStatus()).isEqualTo(CUSTOM_ENTRY_POINT_STATUS);
                });
    }

    @Test
    void moreThanOneCustomEntryPointFailsWithClearMessage() {
        runner.withUserConfiguration(EnabledUserConfig.class, CustomEntryPointConfig.class,
                        SecondCustomEntryPointConfig.class)
                .run(context -> assertThat(context).getFailure()
                        .rootCause()
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("AuthenticationEntryPoint"));
    }

    /**
     * {@code POST} con context path {@code /govpay}, una sessione HTTP gia'
     * aperta (es. nuovo login senza logout) e il cookie CSRF, ma senza
     * l'header CSRF: per una richiesta soggetta al controllo e' un token non
     * valido (403).
     */
    private static MockHttpServletRequest postWithOpenSession(String path) {
        return postWithOpenSession("/govpay", path);
    }

    private static MockHttpServletRequest postWithOpenSession(String contextPath, String path) {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", contextPath + path);
        request.setContextPath(contextPath);
        request.setServletPath(path);
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        request.setRequestedSessionId(session.getId());
        request.setRequestedSessionIdValid(true);
        request.setCookies(new Cookie("XSRF-TOKEN", "token-csrf"));
        request.setContentType("application/json");
        request.setContent(("{\"username\":\"alice\",\"password\":\"" + LOGIN_PASSWORD + "\"}").getBytes());
        return request;
    }

    @Test
    void loginIsExcludedFromCsrfWithContextPath() {
        runner.withUserConfiguration(LoginUserConfig.class)
                .withPropertyValues("govpay.auth.form.enabled=true")
                .run(context -> {
                    MockHttpServletResponse response = perform(context, postWithOpenSession("/auth/login"));
                    assertThat(response.getStatus()).isEqualTo(200);
                });
    }

    @Test
    void loginIsExcludedFromCsrfWithoutContextPath() {
        runner.withUserConfiguration(LoginUserConfig.class)
                .withPropertyValues("govpay.auth.form.enabled=true")
                .run(context -> {
                    MockHttpServletResponse response = perform(context, postWithOpenSession("", "/auth/login"));
                    assertThat(response.getStatus()).isEqualTo(200);
                });
    }

    @Test
    void otherPostWithContextPathStillRequiresCsrf() {
        runner.withUserConfiguration(LoginUserConfig.class)
                .withPropertyValues("govpay.auth.form.enabled=true")
                .run(context -> {
                    MockHttpServletResponse response = perform(context, postWithOpenSession("/api/risorsa"));
                    assertThat(response.getStatus()).isEqualTo(403);
                });
    }

    /**
     * Issue #12: una richiesta anonima respinta con 401 non deve creare una
     * sessione HTTP (la request cache non salva la richiesta).
     */
    @Test
    void anonymousRejectedRequestDoesNotCreateSession() {
        runner.withUserConfiguration(LoginUserConfig.class)
                .withPropertyValues("govpay.auth.form.enabled=true")
                .run(context -> {
                    MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/risorsa");
                    MockHttpServletResponse response = perform(context, request);
                    assertThat(response.getStatus()).isEqualTo(401);
                    assertThat(request.getSession(false)).isNull();
                });
    }

    @Test
    void formLoginStillCreatesSession() {
        runner.withUserConfiguration(LoginUserConfig.class)
                .withPropertyValues("govpay.auth.form.enabled=true")
                .run(context -> {
                    MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/login");
                    request.setServletPath("/auth/login");
                    request.setContentType("application/json");
                    request.setContent(("{\"username\":\"alice\",\"password\":\"" + LOGIN_PASSWORD + "\"}")
                            .getBytes());
                    MockHttpServletResponse response = perform(context, request);
                    assertThat(response.getStatus()).isEqualTo(200);
                    assertThat(request.getSession(false)).isNotNull();
                });
    }

    private static final String LOGIN_PASSWORD = "segreta";

    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class LoginUserConfig {
        @Bean
        GovpayPrincipalLoader loader() {
            String hash = new GovpayPasswordEncoder(false).encode(LOGIN_PASSWORD);
            return (principal, authType) -> new AuthenticatedSubject(principal, hash, true, List.of("OPERATORE"));
        }
    }

    private static final int CUSTOM_ENTRY_POINT_STATUS = 418;

    @Configuration(proxyBeanMethods = false)
    static class CustomEntryPointConfig {
        @Bean
        AuthenticationEntryPoint customEntryPoint() {
            return (request, response, ex) -> response.setStatus(CUSTOM_ENTRY_POINT_STATUS);
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class SecondCustomEntryPointConfig {
        @Bean
        AuthenticationEntryPoint secondCustomEntryPoint() {
            return (request, response, ex) -> response.setStatus(CUSTOM_ENTRY_POINT_STATUS);
        }
    }

    private static JwtDecoder fixedDecoder() {
        return token -> Jwt.withTokenValue(token)
                .header("alg", "RS256")
                .claim("sub", "alice")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(60))
                .build();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class EnabledUserConfig {
        @Bean
        GovpayPrincipalLoader loader() {
            return (principal, authType) -> new AuthenticatedSubject(principal, null, true, List.of("OPERATORE"));
        }

        @Bean
        JwtDecoder jwtDecoder() {
            return fixedDecoder();
        }
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class DisabledUserConfig {
        @Bean
        GovpayPrincipalLoader loader() {
            return (principal, authType) -> new AuthenticatedSubject(principal, null, false, List.of("OPERATORE"));
        }

        @Bean
        JwtDecoder jwtDecoder() {
            return fixedDecoder();
        }
    }
}
