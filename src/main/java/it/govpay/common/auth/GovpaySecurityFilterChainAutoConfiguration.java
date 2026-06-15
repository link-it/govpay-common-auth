package it.govpay.common.auth;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import it.govpay.common.auth.spi.GovpayPrincipalLoader;

/**
 * Auto-configuration che registra la {@link SecurityFilterChain} unica della
 * libreria. La chain implementa il modello "chain unica auto-detect" deciso
 * per V2 (vedi conversazioni di design issue link-it/govpay-console-api#10):
 * un solo {@code securityMatcher("/**")}, dentro la chain ogni filter si
 * attiva sul proprio cue della request (header {@code Authorization: Basic},
 * cookie sessione, certificato SSL, ...).
 *
 * <p>Step 3 (questo): porting del filter BASIC come primo elemento della
 * chain. Step 4+ aggiungeranno FORM/SSL/SPID/API_KEY/SESSION/OAUTH2.
 *
 * <p>La chain si registra solo se il consumer ha esposto un
 * {@link GovpayPrincipalLoader} (SPI obbligatoria). Senza loader la libreria
 * resta dormiente, quindi consumer in transizione (es. console-api a
 * step &lt; 9, che usa ancora la propria {@code SecurityConfig}) non vedono
 * alcuna chain di common-auth.
 */
@AutoConfiguration(after = GovpayAuthAutoConfiguration.class)
@ConditionalOnClass(SecurityFilterChain.class)
@ConditionalOnBean(GovpayPrincipalLoader.class)
@ConditionalOnProperty(prefix = "govpay.auth.basic", name = "enabled")
public class GovpaySecurityFilterChainAutoConfiguration {

    /**
     * Filter che annota la request con l'{@link it.govpay.common.auth.spi.AuthType}
     * applicato dal filter Spring Security che ha vinto. Bean separato per
     * facilitare l'iniezione nelle configurazioni di chain dei consumer.
     */
    @Bean
    public AuthTypeStampingFilter authTypeStampingFilter() {
        return new AuthTypeStampingFilter();
    }

    /**
     * Chain unica V2. Order {@code 50}: prima del catch-all denyAll che
     * potrebbe esistere a {@code 99} ma dopo eventuali chain ad altissima
     * priorita' del consumer (range 1-49 riservato).
     */
    @Bean
    @Order(50)
    public SecurityFilterChain govpaySecurityFilterChain(
            HttpSecurity http,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler,
            AuthTypeStampingFilter authTypeStampingFilter,
            @Qualifier("basicUserDetailsService") UserDetailsService basicUds,
            PasswordEncoder passwordEncoder) throws Exception {

        http
                .securityMatcher("/**")
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(CsrfConfigurer::disable)
                .exceptionHandling(eh -> eh
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .authorizeHttpRequests(a -> a.anyRequest().authenticated());

        // BASIC: attivato solo se l'adapter UDS e' presente
        // (vedi GovpayAuthAutoConfiguration.basicUserDetailsService: dipende
        // a sua volta da govpay.auth.basic.enabled=true).
        DaoAuthenticationProvider basicProvider = new DaoAuthenticationProvider(basicUds);
        basicProvider.setPasswordEncoder(passwordEncoder);
        http.authenticationManager(new ProviderManager(basicProvider));
        http.httpBasic(b -> b.authenticationEntryPoint(authenticationEntryPoint));

        http.addFilterAfter(authTypeStampingFilter, BasicAuthenticationFilter.class);

        return http.build();
    }
}
