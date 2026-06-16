package it.govpay.common.auth;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;

import tools.jackson.databind.ObjectMapper;

import it.govpay.common.auth.spi.AuthEventListener;
import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.AuthenticationDetailsContributor;
import it.govpay.common.auth.spi.GovpayPrincipalLoader;

/**
 * Auto-configuration della libreria common-auth.
 *
 * <p>Foundation step (#2): registra i bean comuni (password encoder, entry
 * point/access denied problem+json, listener no-op) e un
 * {@link GovpayUserDetailsServiceAdapter} per ciascun
 * {@link AuthType} abilitato via {@code govpay.auth.<metodo>.enabled=true}.
 *
 * <p>La registrazione delle {@code SecurityFilterChain} (chain unica
 * auto-detect) e' rimandata agli step successivi: questa classe espone solo
 * i mattoni che le chain consumeranno.
 *
 * <p>Tutti i bean sono {@code @ConditionalOnMissingBean}: il consumer puo'
 * sostituire qualunque pezzo con la propria implementazione senza toccare
 * la libreria.
 */
@AutoConfiguration
@ConditionalOnClass({UserDetailsService.class, ObjectMapper.class})
@EnableConfigurationProperties(GovpayAuthProperties.class)
public class GovpayAuthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(PasswordEncoder.class)
    public PasswordEncoder govpayPasswordEncoder(GovpayAuthProperties properties) {
        return new GovpayPasswordEncoder(properties.getPassword().isMd5FallbackEnabled());
    }

    @Bean
    @ConditionalOnMissingBean(AuthenticationEntryPoint.class)
    public AuthenticationEntryPoint problemAuthenticationEntryPoint(ObjectMapper objectMapper) {
        return new ProblemAuthenticationEntryPoint(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean(AccessDeniedHandler.class)
    public AccessDeniedHandler problemAccessDeniedHandler(ObjectMapper objectMapper) {
        return new ProblemAccessDeniedHandler(objectMapper);
    }

    /**
     * Fallback no-op: se il consumer non registra un proprio
     * {@link AuthEventListener} non vogliamo che il wiring delle chain
     * fallisca per mancanza di dipendenza.
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthEventListener noopAuthEventListener() {
        return new AuthEventListener() {
            // tutti i metodi sono default no-op
        };
    }

    /**
     * Default per {@link AuthenticationDetailsContributor}: delega a
     * {@code WebAuthenticationDetailsSource} di Spring (equivalente al
     * comportamento V1 sui metodi BASIC/FORM/SSL). Il consumer puo'
     * sostituirlo con un proprio bean per catturare header custom,
     * attributi SPID, ecc.
     */
    @Bean
    @ConditionalOnMissingBean
    public AuthenticationDetailsContributor defaultAuthenticationDetailsContributor() {
        return new DefaultAuthenticationDetailsContributor();
    }

    /**
     * {@link HttpFirewall} configurato con le property
     * {@code govpay.auth.firewall.*}. Default V1: {@code allowUrlEncodedSlash=true}
     * e {@code allowUrlEncodedPercent=true} per accettare identificativi
     * pagopa che contengono {@code /} o {@code %} URL-encoded nel path.
     *
     * <p>Spring Boot autodetecta questo bean e lo registra sul
     * {@code WebSecurity} senza ulteriore wiring.
     */
    @Bean
    @ConditionalOnMissingBean(HttpFirewall.class)
    public HttpFirewall httpFirewall(GovpayAuthProperties properties) {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowUrlEncodedSlash(properties.getFirewall().isAllowUrlEncodedSlash());
        firewall.setAllowUrlEncodedPercent(properties.getFirewall().isAllowUrlEncodedPercent());
        return firewall;
    }

    /**
     * Adapter SPI -> {@link UserDetailsService} per la chain BASIC, registrato
     * solo se il consumer ha esposto un {@link GovpayPrincipalLoader} e ha
     * abilitato la chain via property.
     */
    @Bean("basicUserDetailsService")
    @ConditionalOnBean(GovpayPrincipalLoader.class)
    @ConditionalOnProperty(prefix = "govpay.auth.basic", name = "enabled")
    public UserDetailsService basicUserDetailsService(GovpayPrincipalLoader loader) {
        return new GovpayUserDetailsServiceAdapter(loader, AuthType.BASIC);
    }

    @Bean("formUserDetailsService")
    @ConditionalOnBean(GovpayPrincipalLoader.class)
    @ConditionalOnProperty(prefix = "govpay.auth.form", name = "enabled")
    public UserDetailsService formUserDetailsService(GovpayPrincipalLoader loader) {
        return new GovpayUserDetailsServiceAdapter(loader, AuthType.FORM);
    }

    @Bean("sslUserDetailsService")
    @ConditionalOnBean(GovpayPrincipalLoader.class)
    @ConditionalOnProperty(prefix = "govpay.auth.ssl", name = "enabled")
    public UserDetailsService sslUserDetailsService(GovpayPrincipalLoader loader) {
        return new GovpayUserDetailsServiceAdapter(loader, AuthType.SSL);
    }

    @Bean("sslHeaderUserDetailsService")
    @ConditionalOnBean(GovpayPrincipalLoader.class)
    @ConditionalOnProperty(prefix = "govpay.auth.ssl-header", name = "enabled")
    public UserDetailsService sslHeaderUserDetailsService(GovpayPrincipalLoader loader) {
        return new GovpayUserDetailsServiceAdapter(loader, AuthType.SSL_HEADER);
    }

    @Bean("headerUserDetailsService")
    @ConditionalOnBean(GovpayPrincipalLoader.class)
    @ConditionalOnProperty(prefix = "govpay.auth.header", name = "enabled")
    public UserDetailsService headerUserDetailsService(GovpayPrincipalLoader loader) {
        return new GovpayUserDetailsServiceAdapter(loader, AuthType.HEADER);
    }

    @Bean("apiKeyUserDetailsService")
    @ConditionalOnBean(GovpayPrincipalLoader.class)
    @ConditionalOnProperty(prefix = "govpay.auth.api-key", name = "enabled")
    public UserDetailsService apiKeyUserDetailsService(GovpayPrincipalLoader loader) {
        return new GovpayUserDetailsServiceAdapter(loader, AuthType.API_KEY);
    }

    @Bean("spidUserDetailsService")
    @ConditionalOnBean(GovpayPrincipalLoader.class)
    @ConditionalOnProperty(prefix = "govpay.auth.spid", name = "enabled")
    public UserDetailsService spidUserDetailsService(GovpayPrincipalLoader loader) {
        return new GovpayUserDetailsServiceAdapter(loader, AuthType.SPID);
    }

    @Bean("sessionUserDetailsService")
    @ConditionalOnBean(GovpayPrincipalLoader.class)
    @ConditionalOnProperty(prefix = "govpay.auth.session", name = "enabled")
    public UserDetailsService sessionUserDetailsService(GovpayPrincipalLoader loader) {
        return new GovpayUserDetailsServiceAdapter(loader, AuthType.SESSION);
    }

    @Bean("oauth2UserDetailsService")
    @ConditionalOnBean(GovpayPrincipalLoader.class)
    @ConditionalOnProperty(prefix = "govpay.auth.oauth2", name = "enabled")
    public UserDetailsService oauth2UserDetailsService(GovpayPrincipalLoader loader) {
        return new GovpayUserDetailsServiceAdapter(loader, AuthType.OAUTH2);
    }

    @Bean("ldapUserDetailsService")
    @ConditionalOnBean(GovpayPrincipalLoader.class)
    @ConditionalOnProperty(prefix = "govpay.auth.ldap", name = "enabled")
    public UserDetailsService ldapUserDetailsService(GovpayPrincipalLoader loader) {
        return new GovpayUserDetailsServiceAdapter(loader, AuthType.LDAP);
    }
}
