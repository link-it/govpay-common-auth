package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.security.autoconfigure.SecurityAutoConfiguration;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import it.govpay.common.auth.spi.AuthenticatedSubject;
import it.govpay.common.auth.spi.GovpayPrincipalLoader;
import it.govpay.common.auth.spi.JsonLoginResponseWriter;

class GovpaySecurityFilterChainAutoConfigurationTest {

    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withBean(ObjectMapper.class, () -> JsonMapper.builder().build())
            .withConfiguration(AutoConfigurations.of(
                    SecurityAutoConfiguration.class,
                    GovpayAuthAutoConfiguration.class,
                    GovpaySecurityFilterChainAutoConfiguration.class));

    @Test
    void chainAndStampingFilterRegisteredWhenBasicEnabledAndLoaderPresent() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues("govpay.auth.basic.enabled=true")
                .run(context -> {
                    assertThat(context).hasSingleBean(SecurityFilterChain.class);
                    assertThat(context).hasSingleBean(AuthTypeStampingFilter.class);
                    assertThat(context).doesNotHaveBean(JsonUsernamePasswordAuthenticationFilter.class);
                });
    }

    @Test
    void chainNotRegisteredWhenLoaderMissing() {
        runner.withPropertyValues("govpay.auth.basic.enabled=true")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(SecurityFilterChain.class);
                    assertThat(context).doesNotHaveBean(AuthTypeStampingFilter.class);
                });
    }

    @Test
    void chainAndFormFilterRegisteredWhenFormEnabled() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues("govpay.auth.form.enabled=true")
                .run(context -> {
                    assertThat(context).hasSingleBean(SecurityFilterChain.class);
                    assertThat(context).hasSingleBean(JsonUsernamePasswordAuthenticationFilter.class);
                    assertThat(context).hasSingleBean(LoginRateLimiter.class);
                    assertThat(context).hasSingleBean(JsonLoginResponseWriter.class);
                });
    }

    @Test
    void basicAndFormCanCoexist() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues(
                        "govpay.auth.basic.enabled=true",
                        "govpay.auth.form.enabled=true")
                .run(context -> {
                    assertThat(context).hasSingleBean(SecurityFilterChain.class);
                    assertThat(context).hasSingleBean(JsonUsernamePasswordAuthenticationFilter.class);
                });
    }

    @Test
    void formBeansAbsentWhenFormDisabled() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues("govpay.auth.basic.enabled=true")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(JsonUsernamePasswordAuthenticationFilter.class);
                    assertThat(context).doesNotHaveBean(LoginRateLimiter.class);
                    assertThat(context).doesNotHaveBean(JsonLoginResponseWriter.class);
                });
    }

    @Test
    void headerFilterRegisteredWhenHeaderEnabled() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues("govpay.auth.header.enabled=true")
                .run(context -> {
                    assertThat(context).hasSingleBean(HeaderPreAuthenticationFilter.class);
                    assertThat(context).doesNotHaveBean(SslHeaderPreAuthenticationFilter.class);
                    assertThat(context).doesNotHaveBean(ApiKeyAuthenticationFilter.class);
                });
    }

    @Test
    void sslHeaderFilterRegisteredWhenSslHeaderEnabled() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues("govpay.auth.ssl-header.enabled=true")
                .run(context -> {
                    assertThat(context).hasSingleBean(SslHeaderPreAuthenticationFilter.class);
                });
    }

    @Test
    void apiKeyFilterRegisteredWhenApiKeyEnabled() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues("govpay.auth.api-key.enabled=true")
                .run(context -> {
                    assertThat(context).hasSingleBean(ApiKeyAuthenticationFilter.class);
                });
    }

    @Test
    void allMethodsCanCoexist() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues(
                        "govpay.auth.basic.enabled=true",
                        "govpay.auth.form.enabled=true",
                        "govpay.auth.ssl.enabled=true",
                        "govpay.auth.header.enabled=true",
                        "govpay.auth.ssl-header.enabled=true",
                        "govpay.auth.api-key.enabled=true",
                        "govpay.auth.spid.enabled=true",
                        "govpay.auth.spid.principal-header-name=X-SPID-SubjectCF",
                        "govpay.auth.session.enabled=true")
                .run(context -> {
                    assertThat(context).hasSingleBean(SecurityFilterChain.class);
                    assertThat(context).hasSingleBean(JsonUsernamePasswordAuthenticationFilter.class);
                    assertThat(context).hasSingleBean(HeaderPreAuthenticationFilter.class);
                    assertThat(context).hasSingleBean(SslHeaderPreAuthenticationFilter.class);
                    assertThat(context).hasSingleBean(ApiKeyAuthenticationFilter.class);
                    assertThat(context).hasSingleBean(SpidPreAuthenticationFilter.class);
                    assertThat(context).hasSingleBean(SessionPreAuthenticationFilter.class);
                });
    }

    @Test
    void spidFilterRegisteredWhenSpidEnabled() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues(
                        "govpay.auth.spid.enabled=true",
                        "govpay.auth.spid.principal-header-name=X-SPID-SubjectCF")
                .run(context -> assertThat(context).hasSingleBean(SpidPreAuthenticationFilter.class));
    }

    @Test
    void spidFilterFailsWhenPrincipalHeaderMissing() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues("govpay.auth.spid.enabled=true")
                .run(context -> assertThat(context).hasFailed());
    }

    @Test
    void sessionFilterRegisteredWhenSessionEnabled() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues("govpay.auth.session.enabled=true")
                .run(context -> assertThat(context).hasSingleBean(SessionPreAuthenticationFilter.class));
    }

    @Test
    void ldapFilterRegisteredWhenLdapEnabled() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues(
                        "govpay.auth.ldap.enabled=true",
                        "govpay.auth.ldap.url=ldap://localhost:33389/dc=example,dc=com",
                        "govpay.auth.ldap.user-dn-pattern=uid={0},ou=people")
                .run(context -> assertThat(context).hasSingleBean(LdapAuthenticationFilter.class));
    }

    @Test
    void corsConfigurationSourceRegisteredWhenCorsEnabled() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues(
                        "govpay.auth.basic.enabled=true",
                        "govpay.auth.cors.enabled=true",
                        "govpay.auth.cors.allow-all-origin=true")
                .run(context -> assertThat(context).hasSingleBean(
                        org.springframework.web.cors.CorsConfigurationSource.class));
    }

    @Test
    void oauth2BeansRegisteredWhenOauth2Enabled() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues(
                        "govpay.auth.oauth2.enabled=true",
                        "govpay.auth.oauth2.jwk-set-uri=https://idp.example.com/.well-known/jwks.json")
                .run(context -> {
                    assertThat(context).hasSingleBean(org.springframework.security.oauth2.jwt.JwtDecoder.class);
                    assertThat(context).hasSingleBean(GovpayJwtAuthenticationConverter.class);
                    assertThat(context).hasSingleBean(BearerTokenProblemAuthenticationEntryPoint.class);
                });
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class LoaderConfig {
        @Bean
        GovpayPrincipalLoader loader() {
            return (principal, authType) -> new AuthenticatedSubject(
                    principal, "$6$x$y", true, List.of("OPERATORE"));
        }
    }
}
