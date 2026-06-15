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
    void chainNotRegisteredWhenBasicDisabled() {
        runner.withUserConfiguration(LoaderConfig.class)
                .run(context -> {
                    assertThat(context).doesNotHaveBean(SecurityFilterChain.class);
                    assertThat(context).doesNotHaveBean(AuthTypeStampingFilter.class);
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
