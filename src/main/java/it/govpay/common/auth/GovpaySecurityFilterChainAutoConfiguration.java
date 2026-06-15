package it.govpay.common.auth;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

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
import org.springframework.security.authentication.AuthenticationProvider;
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
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import tools.jackson.databind.ObjectMapper;

import it.govpay.common.auth.spi.AuthEventListener;
import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.AuthenticationDetailsContributor;
import it.govpay.common.auth.spi.GovpayPrincipalLoader;
import it.govpay.common.auth.spi.JsonLoginResponseWriter;

/**
 * Auto-configuration che assembla la {@link SecurityFilterChain} unica della
 * libreria con i filter dei metodi auth abilitati.
 *
 * <p>Modello: una sola chain ({@code securityMatcher("/**")}). Dentro la
 * chain coesistono filter di Spring Security (Basic, X509, LogoutFilter, ...)
 * e filter custom della libreria (JsonLogin, HeaderPreAuth, SslHeaderPreAuth,
 * ApiKey, AuthTypeStamping); ciascuno si attiva sul proprio "cue" della
 * request.
 *
 * <p>Distribuzione manager: BASIC e SSL contribuiscono al manager di default
 * della chain (entrambi sono triggerati da filter Spring built-in che usano
 * quel manager). Gli altri metodi (FORM, API_KEY, HEADER, SSL_HEADER) hanno
 * filter custom con manager dedicato, in modo da preservare la
 * discriminazione per {@code AuthType} nel loader.
 */
@AutoConfiguration(after = GovpayAuthAutoConfiguration.class)
@ConditionalOnClass(SecurityFilterChain.class)
@ConditionalOnBean(GovpayPrincipalLoader.class)
public class GovpaySecurityFilterChainAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public AuthTypeStampingFilter authTypeStampingFilter(GovpayAuthProperties properties) {
        return new AuthTypeStampingFilter(properties);
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
            AuthenticationDetailsContributor detailsContributor,
            @Qualifier("formUserDetailsService") UserDetailsService formUds,
            PasswordEncoder passwordEncoder) {
        JsonUsernamePasswordAuthenticationFilter filter = new JsonUsernamePasswordAuthenticationFilter(
                properties.getForm().getLoginPath(),
                objectMapper, responseWriter, eventListener, rateLimiter, detailsContributor);
        filter.setAuthenticationManager(new ProviderManager(daoProvider(formUds, passwordEncoder)));
        return filter;
    }

    @Bean
    @ConditionalOnProperty(prefix = "govpay.auth.header", name = "enabled")
    public HeaderPreAuthenticationFilter headerPreAuthenticationFilter(
            GovpayAuthProperties properties,
            AuthenticationDetailsContributor detailsContributor,
            @Qualifier("headerUserDetailsService") UserDetailsService headerUds) {
        HeaderPreAuthenticationFilter filter = new HeaderPreAuthenticationFilter(
                properties.getHeader().getPrincipalHeaderNames());
        filter.setAuthenticationManager(new ProviderManager(preAuthProvider(headerUds)));
        filter.setAuthenticationDetailsSource(request -> detailsContributor.buildDetails(request, AuthType.HEADER));
        return filter;
    }

    @Bean
    @ConditionalOnProperty(prefix = "govpay.auth.ssl-header", name = "enabled")
    public SslHeaderPreAuthenticationFilter sslHeaderPreAuthenticationFilter(
            GovpayAuthProperties properties,
            AuthenticationDetailsContributor detailsContributor,
            @Qualifier("sslHeaderUserDetailsService") UserDetailsService sslHeaderUds) {
        SslHeaderPreAuthenticationFilter filter = new SslHeaderPreAuthenticationFilter(properties.getSslHeader());
        filter.setAuthenticationManager(new ProviderManager(preAuthProvider(sslHeaderUds)));
        filter.setAuthenticationDetailsSource(request -> detailsContributor.buildDetails(request, AuthType.SSL_HEADER));
        return filter;
    }

    @Bean
    @ConditionalOnProperty(prefix = "govpay.auth.api-key", name = "enabled")
    public ApiKeyAuthenticationFilter apiKeyAuthenticationFilter(
            GovpayAuthProperties properties,
            AuthenticationDetailsContributor detailsContributor,
            @Qualifier("apiKeyUserDetailsService") UserDetailsService apiKeyUds,
            PasswordEncoder passwordEncoder) {
        return new ApiKeyAuthenticationFilter(
                properties.getApiKey().getIdHeaderName(),
                properties.getApiKey().getKeyHeaderName(),
                new ProviderManager(daoProvider(apiKeyUds, passwordEncoder)),
                detailsContributor);
    }

    @Bean
    @Order(50)
    public SecurityFilterChain govpaySecurityFilterChain(
            HttpSecurity http,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler,
            AuthTypeStampingFilter authTypeStampingFilter,
            ObjectProvider<JsonUsernamePasswordAuthenticationFilter> jsonLoginFilterProvider,
            ObjectProvider<HeaderPreAuthenticationFilter> headerFilterProvider,
            ObjectProvider<SslHeaderPreAuthenticationFilter> sslHeaderFilterProvider,
            ObjectProvider<ApiKeyAuthenticationFilter> apiKeyFilterProvider,
            @Qualifier("basicUserDetailsService") ObjectProvider<UserDetailsService> basicUdsProvider,
            @Qualifier("sslUserDetailsService") ObjectProvider<UserDetailsService> sslUdsProvider,
            PasswordEncoder passwordEncoder,
            GovpayAuthProperties properties,
            AuthEventListener eventListener,
            ObjectMapper objectMapper) throws Exception {

        GovpayAuthProperties.Form form = properties.getForm();
        boolean formEnabled = form.isEnabled();

        http.securityMatcher("/**")
                .exceptionHandling(eh -> eh
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler))
                .authorizeHttpRequests(a -> a.anyRequest().authenticated());

        configureHeaders(http, properties.getHeaders());
        configureSession(http, formEnabled, objectMapper);
        configureCsrf(http, form, formEnabled);
        configureChainManagerAndBuiltins(http, properties, basicUdsProvider, sslUdsProvider,
                passwordEncoder, authenticationEntryPoint);
        configureFormLogout(http, form, formEnabled, eventListener);

        // Filter custom della libreria: posizionati prima/dopo Basic per ordine deterministico.
        jsonLoginFilterProvider.ifAvailable(f -> http.addFilterBefore(f, BasicAuthenticationFilter.class));
        apiKeyFilterProvider.ifAvailable(f -> http.addFilterBefore(f, BasicAuthenticationFilter.class));
        headerFilterProvider.ifAvailable(f -> http.addFilterBefore(f, BasicAuthenticationFilter.class));
        sslHeaderFilterProvider.ifAvailable(f -> http.addFilterBefore(f, BasicAuthenticationFilter.class));
        http.addFilterAfter(authTypeStampingFilter, BasicAuthenticationFilter.class);

        return http.build();
    }

    private static DaoAuthenticationProvider daoProvider(UserDetailsService uds, PasswordEncoder encoder) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(uds);
        provider.setPasswordEncoder(encoder);
        return provider;
    }

    private static PreAuthenticatedAuthenticationProvider preAuthProvider(UserDetailsService uds) {
        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
        provider.setPreAuthenticatedUserDetailsService(new UserDetailsByNameServiceWrapper<>(uds));
        return provider;
    }

    private static void configureHeaders(HttpSecurity http,
                                         GovpayAuthProperties.Headers headers) throws Exception {
        http.headers(h -> {
            if (!headers.isContentTypeOptionsEnabled()) {
                h.contentTypeOptions(c -> c.disable());
            }
            if (!headers.isFrameOptionsEnabled()) {
                h.frameOptions(f -> f.disable());
            }
            if (!headers.isXssProtectionEnabled()) {
                h.xssProtection(x -> x.disable());
            }
        });
    }

    private static void configureSession(HttpSecurity http,
                                         boolean formEnabled,
                                         ObjectMapper objectMapper) throws Exception {
        if (formEnabled) {
            // Replica V1: session invalida / scaduta -> 401 problem+json
            // (NotAuthorizedInvalidSessionStrategy + NotAuthorizedSessionInformationExpiredStrategy).
            ProblemInvalidSessionStrategy invalidSession = new ProblemInvalidSessionStrategy(objectMapper);
            ProblemSessionInformationExpiredStrategy expiredSession =
                    new ProblemSessionInformationExpiredStrategy(objectMapper);
            http.sessionManagement(s -> s
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .sessionFixation(fixation -> fixation.changeSessionId())
                    .invalidSessionStrategy(invalidSession)
                    .maximumSessions(2)
                    .expiredSessionStrategy(expiredSession));
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
            if ("POST".equalsIgnoreCase(request.getMethod()) && loginPath.equals(request.getRequestURI())) {
                return true;
            }
            if (request.getHeader("Authorization") != null) {
                return true;
            }
            return request.getRequestedSessionId() == null;
        };
        http.csrf(c -> c.csrfTokenRepository(repo).ignoringRequestMatchers(ignore));
    }

    /**
     * Costruisce il manager di default della chain (usato da BasicAuthenticationFilter
     * e X509AuthenticationFilter) con i provider per BASIC e SSL, e attiva
     * i corrispondenti filter built-in di Spring Security.
     */
    private static void configureChainManagerAndBuiltins(
            HttpSecurity http,
            GovpayAuthProperties properties,
            ObjectProvider<UserDetailsService> basicUdsProvider,
            ObjectProvider<UserDetailsService> sslUdsProvider,
            PasswordEncoder passwordEncoder,
            AuthenticationEntryPoint entryPoint) throws Exception {
        List<AuthenticationProvider> providers = new ArrayList<>();
        boolean basicActive = properties.getBasic().isEnabled() && basicUdsProvider.getIfAvailable() != null;
        boolean sslActive = properties.getSsl().isEnabled() && sslUdsProvider.getIfAvailable() != null;
        if (basicActive) {
            providers.add(daoProvider(basicUdsProvider.getObject(), passwordEncoder));
        }
        if (sslActive) {
            providers.add(preAuthProvider(sslUdsProvider.getObject()));
        }
        if (!providers.isEmpty()) {
            http.authenticationManager(new ProviderManager(providers));
        }
        if (basicActive) {
            http.httpBasic(b -> b.authenticationEntryPoint(entryPoint));
        }
        if (sslActive) {
            String regex = properties.getSsl().getSubjectPrincipalRegex();
            http.x509(x -> x
                    .subjectPrincipalRegex(regex)
                    .userDetailsService(sslUdsProvider.getObject()));
        }
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
