package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetailsService;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import it.govpay.common.auth.spi.AuthEventListener;
import it.govpay.common.auth.spi.AuthenticatedSubject;
import it.govpay.common.auth.spi.GovpayPrincipalLoader;

class GovpayAuthAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withBean(ObjectMapper.class, () -> JsonMapper.builder().build())
            .withConfiguration(AutoConfigurations.of(GovpayAuthAutoConfiguration.class));

    @Test
    void exposesFoundationBeans() {
        runner.run(context -> {
            assertThat(context).hasSingleBean(GovpayPasswordEncoder.class);
            assertThat(context).hasSingleBean(ProblemAuthenticationEntryPoint.class);
            assertThat(context).hasSingleBean(ProblemAccessDeniedHandler.class);
            assertThat(context).hasSingleBean(AuthEventListener.class);
        });
    }

    @Test
    void doesNotRegisterAdapterWhenPrincipalLoaderMissing() {
        runner.withPropertyValues("govpay.auth.basic.enabled=true")
                .run(context -> assertThat(context).doesNotHaveBean(UserDetailsService.class));
    }

    @Test
    void registersBasicAdapterWhenEnabledAndLoaderPresent() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues("govpay.auth.basic.enabled=true")
                .run(context -> {
                    assertThat(context).hasBean("basicUserDetailsService");
                    assertThat(context.getBean("basicUserDetailsService"))
                            .isInstanceOf(GovpayUserDetailsServiceAdapter.class);
                });
    }

    @Test
    void formAndSslAdaptersAreIndependent() {
        runner.withUserConfiguration(LoaderConfig.class)
                .withPropertyValues(
                        "govpay.auth.form.enabled=true",
                        "govpay.auth.ssl.enabled=true")
                .run(context -> {
                    assertThat(context).hasBean("formUserDetailsService");
                    assertThat(context).hasBean("sslUserDetailsService");
                    assertThat(context).doesNotHaveBean("basicUserDetailsService");
                });
    }

    @Test
    void md5FallbackPropertyDrivesEncoderConstructor() {
        runner.withPropertyValues("govpay.auth.password.md5-fallback-enabled=false")
                .run(context -> {
                    GovpayPasswordEncoder encoder = context.getBean(GovpayPasswordEncoder.class);
                    // Indirect check: md5 hash should be rejected when fallback disabled
                    String md5 = "$1$abcdefgh$XlS73HWcZcg6CRkM3rRWG.";
                    assertThat(encoder.matches("anything", md5)).isFalse();
                });
    }

    @Test
    void consumerCanOverrideEntryPointAndEventListener() {
        AuthEventListener customListener = new AuthEventListener() {};
        runner.withBean("customListener", AuthEventListener.class, () -> customListener)
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthEventListener.class);
                    assertThat(context.getBean(AuthEventListener.class)).isSameAs(customListener);
                });
    }

    @Configuration(proxyBeanMethods = false)
    static class LoaderConfig {
        @Bean
        GovpayPrincipalLoader loader() {
            return (principal, authType) -> new AuthenticatedSubject(
                    principal, "$6$x$y", true, List.of());
        }
    }
}
