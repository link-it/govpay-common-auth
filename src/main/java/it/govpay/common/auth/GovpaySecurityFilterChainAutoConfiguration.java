package it.govpay.common.auth;

import java.time.Duration;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
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
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import tools.jackson.databind.ObjectMapper;

import it.govpay.common.auth.spi.AuthEventListener;
import it.govpay.common.auth.spi.GovpayPrincipalLoader;
import it.govpay.common.auth.spi.JsonLoginResponseWriter;

/**
 * Auto-configuration che assembla la {@link SecurityFilterChain} unica della
 * libreria con i filter dei metodi auth abilitati.
 *
 * <p>Modello: una sola chain ({@code securityMatcher("/**")}). Dentro la chain
 * coesistono i filter di Spring Security ({@code BasicAuthenticationFilter},
 * {@code LogoutFilter}, ...) e i filter custom della libreria
 * ({@code JsonUsernamePasswordAuthenticationFilter},
 * {@code AuthTypeStampingFilter}); ciascuno si attiva sul proprio "cue"
 * della request (header {@code Authorization: Basic}, body JSON su
 * {@code POST /auth/login}, ...).
 *
 * <p>La chain si registra solo se il consumer ha esposto un
 * {@link GovpayPrincipalLoader}. Il comportamento puntuale (CSRF, session
 * policy, filter aggiunti) si adatta alle property
 * {@code govpay.auth.<metodo>.enabled}.
 */
@AutoConfiguration(after = GovpayAuthAutoConfiguration.class)
@ConditionalOnClass(SecurityFilterChain.class)
@ConditionalOnBean(GovpayPrincipalLoader.class)
public class GovpaySecurityFilterChainAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AuthTypeStampingFilter authTypeStampingFilter() {
        return new AuthTypeStampingFilter();
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "govpay.auth.form", name = "enabled")
    public LoginRateLimiter loginRateLimiter(GovpayAuthProperties properties) {
        GovpayAuthProperties.RateLimit rl = properties.getForm().getRateLimit();
        return new LoginRateLimiter(rl.getAttempts(), Duration.ofMinutes(rl.getWindowMinutes()));
    }

    @Bean
    @ConditionalOnMissingBean(JsonLoginResponseWriter.class)
    @ConditionalOnProperty(prefix = "govpay.auth.form", name = "enabled")
    public JsonLoginResponseWriter defaultJsonLoginResponseWriter(ObjectMapper objectMapper) {
        return new DefaultJsonLoginResponseWriter(objectMapper);
    }

    @Bean
    @ConditionalOnProperty(prefix = "govpay.auth.form", name = "enabled")
    public JsonUsernamePasswordAuthenticationFilter jsonLoginFilter(
            GovpayAuthProperties properties,
            ObjectMapper objectMapper,
            JsonLoginResponseWriter responseWriter,
            AuthEventListener eventListener,
            LoginRateLimiter rateLimiter,
            @Qualifier("formUserDetailsService") UserDetailsService formUds,
            PasswordEncoder passwordEncoder) {
        JsonUsernamePasswordAuthenticationFilter filter = new JsonUsernamePasswordAuthenticationFilter(
                properties.getForm().getLoginPath(),
                objectMapper, responseWriter, eventListener, rateLimiter);
        DaoAuthenticationProvider formProvider = new DaoAuthenticationProvider(formUds);
        formProvider.setPasswordEncoder(passwordEncoder);
        filter.setAuthenticationManager(new ProviderManager(formProvider));
        return filter;
    }

    @Bean
    @Order(50)
    public SecurityFilterChain govpaySecurityFilterChain(
            HttpSecurity http,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler,
            AuthTypeStampingFilter authTypeStampingFilter,
            ObjectProvider<JsonUsernamePasswordAuthenticationFilter> jsonLoginFilterProvider,
            @Qualifier("basicUserDetailsService") ObjectProvider<UserDetailsService> basicUdsProvider,
            PasswordEncoder passwordEncoder,
            GovpayAuthProperties properties,
            AuthEventListener eventListener) throws Exception {

        GovpayAuthProperties.Form form = properties.getForm();
        boolean formEnabled = form.isEnabled();

        http.securityMatcher("/**")
                .exceptionHandling(eh -> eh
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .authorizeHttpRequests(a -> a.anyRequest().authenticated());

        configureSession(http, formEnabled);
        configureCsrf(http, form, formEnabled);
        configureBasic(http, basicUdsProvider, passwordEncoder, properties, authenticationEntryPoint);
        configureFormLogout(http, form, formEnabled, eventListener);

        // I filter custom della libreria
        jsonLoginFilterProvider.ifAvailable(f -> http.addFilterAfter(f, BasicAuthenticationFilter.class));
        http.addFilterAfter(authTypeStampingFilter, BasicAuthenticationFilter.class);

        return http.build();
    }

    private static void configureSession(HttpSecurity http, boolean formEnabled) throws Exception {
        if (formEnabled) {
            http.sessionManagement(s -> s
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .sessionFixation(fixation -> fixation.changeSessionId()));
        } else {
            http.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        }
    }

    private static void configureCsrf(HttpSecurity http,
                                      GovpayAuthProperties.Form form,
                                      boolean formEnabled) throws Exception {
        if (!formEnabled) {
            http.csrf(CsrfConfigurer::disable);
            return;
        }
        CookieCsrfTokenRepository repo = CookieCsrfTokenRepository.withHttpOnlyFalse();
        repo.setCookieName(form.getCsrfCookieName());
        repo.setHeaderName(form.getCsrfHeaderName());
        String loginPath = form.getLoginPath();
        RequestMatcher ignore = request -> {
            // Il login stesso emette il token: non puo' richiederlo.
            if ("POST".equalsIgnoreCase(request.getMethod()) && loginPath.equals(request.getRequestURI())) {
                return true;
            }
            // Stateless: header Authorization presente -> niente CSRF.
            if (request.getHeader("Authorization") != null) {
                return true;
            }
            // Niente cookie sessione = nessuna possibilita' di CSRF.
            return request.getRequestedSessionId() == null;
        };
        http.csrf(c -> c.csrfTokenRepository(repo).ignoringRequestMatchers(ignore));
    }

    private static void configureBasic(HttpSecurity http,
                                       ObjectProvider<UserDetailsService> basicUdsProvider,
                                       PasswordEncoder passwordEncoder,
                                       GovpayAuthProperties properties,
                                       AuthenticationEntryPoint entryPoint) throws Exception {
        if (!properties.getBasic().isEnabled()) {
            return;
        }
        UserDetailsService basicUds = basicUdsProvider.getIfAvailable();
        if (basicUds == null) {
            return;
        }
        DaoAuthenticationProvider basicProvider = new DaoAuthenticationProvider(basicUds);
        basicProvider.setPasswordEncoder(passwordEncoder);
        http.authenticationManager(new ProviderManager(basicProvider));
        http.httpBasic(b -> b.authenticationEntryPoint(entryPoint));
    }

    private static void configureFormLogout(HttpSecurity http,
                                            GovpayAuthProperties.Form form,
                                            boolean formEnabled,
                                            AuthEventListener eventListener) throws Exception {
        if (!formEnabled) {
            return;
        }
        RequestMatcher logoutMatcher = PathPatternRequestMatcher.withDefaults()
                .matcher(HttpMethod.POST, form.getLogoutPath());
        http.logout(l -> l
                .logoutRequestMatcher(logoutMatcher)
                .logoutSuccessHandler(new GovpayLogoutSuccessHandler(eventListener))
                .deleteCookies("JSESSIONID", form.getCsrfCookieName())
                .invalidateHttpSession(true)
                .clearAuthentication(true));
    }
}
