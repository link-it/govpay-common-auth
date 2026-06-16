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
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import tools.jackson.databind.ObjectMapper;

import it.govpay.common.auth.spi.AuthEventListener;
import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.AuthenticationDetailsContributor;
import it.govpay.common.auth.spi.AuthenticatedSubject;
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
    @ConditionalOnProperty(prefix = "govpay.auth.spid", name = "enabled")
    public SpidPreAuthenticationFilter spidPreAuthenticationFilter(
            GovpayAuthProperties properties,
            AuthenticationDetailsContributor detailsContributor,
            @Qualifier("spidUserDetailsService") UserDetailsService spidUds) {
        SpidPreAuthenticationFilter filter = new SpidPreAuthenticationFilter(
                properties.getSpid().getPrincipalHeaderName(),
                properties.getSpid().getTinitPrefix());
        filter.setAuthenticationManager(new ProviderManager(preAuthProvider(spidUds)));
        filter.setAuthenticationDetailsSource(req -> detailsContributor.buildDetails(req, AuthType.SPID));
        return filter;
    }

    @Bean
    @ConditionalOnProperty(prefix = "govpay.auth.session", name = "enabled")
    public SessionPreAuthenticationFilter sessionPreAuthenticationFilter(
            GovpayAuthProperties properties,
            AuthenticationDetailsContributor detailsContributor,
            @Qualifier("sessionUserDetailsService") UserDetailsService sessionUds) {
        SessionPreAuthenticationFilter filter = new SessionPreAuthenticationFilter(
                properties.getSession().getSessionPrincipalAttributeName());
        filter.setAuthenticationManager(new ProviderManager(preAuthProvider(sessionUds)));
        filter.setAuthenticationDetailsSource(req -> detailsContributor.buildDetails(req, AuthType.SESSION));
        return filter;
    }

    @Bean
    @ConditionalOnProperty(prefix = "govpay.auth.ldap", name = "enabled")
    public LdapAuthenticationFilter ldapAuthenticationFilter(
            GovpayAuthProperties properties,
            AuthenticationDetailsContributor detailsContributor,
            GovpayPrincipalLoader principalLoader) {
        GovpayAuthProperties.Ldap ldap = properties.getLdap();
        if (ldap.getUrl() == null || ldap.getUrl().isBlank()) {
            throw new IllegalStateException("govpay.auth.ldap.enabled=true ma govpay.auth.ldap.url e' assente");
        }
        DefaultSpringSecurityContextSource ctxSource = new DefaultSpringSecurityContextSource(ldap.getUrl());
        if (ldap.getManagerDn() != null && !ldap.getManagerDn().isBlank()) {
            ctxSource.setUserDn(ldap.getManagerDn());
            ctxSource.setPassword(ldap.getManagerPassword());
        }
        ctxSource.afterPropertiesSet();

        BindAuthenticator bindAuthenticator = new BindAuthenticator(ctxSource);
        if (ldap.getUserDnPattern() != null && !ldap.getUserDnPattern().isBlank()) {
            bindAuthenticator.setUserDnPatterns(new String[]{ldap.getUserDnPattern()});
        }
        if (ldap.getUserSearchFilter() != null && !ldap.getUserSearchFilter().isBlank()) {
            FilterBasedLdapUserSearch search = new FilterBasedLdapUserSearch(
                    ldap.getUserSearchBase() == null ? "" : ldap.getUserSearchBase(),
                    ldap.getUserSearchFilter(),
                    ctxSource);
            bindAuthenticator.setUserSearch(search);
        }

        DefaultLdapAuthoritiesPopulator authoritiesPopulator = new DefaultLdapAuthoritiesPopulator(
                ctxSource, ldap.getGroupSearchBase());
        authoritiesPopulator.setGroupSearchFilter(ldap.getGroupSearchFilter());
        authoritiesPopulator.setRolePrefix(ldap.getRolePrefix());
        authoritiesPopulator.setConvertToUpperCase(ldap.isConvertToUpperCase());

        LdapAuthenticationProvider provider = new LdapAuthenticationProvider(bindAuthenticator, authoritiesPopulator);
        provider.setUserDetailsContextMapper(new GovpayLdapUserDetailsContextMapper(
                principalLoader, ldap.getRolePrefix(), ldap.isConvertToUpperCase()));

        return new LdapAuthenticationFilter(new ProviderManager(provider), detailsContributor);
    }

    @Bean
    @ConditionalOnMissingBean(JwtDecoder.class)
    @ConditionalOnProperty(prefix = "govpay.auth.oauth2", name = "enabled")
    public JwtDecoder govpayJwtDecoder(GovpayAuthProperties properties) {
        GovpayAuthProperties.Oauth2 oauth2 = properties.getOauth2();
        if (oauth2.getJwkSetUri() == null || oauth2.getJwkSetUri().isBlank()) {
            throw new IllegalStateException("govpay.auth.oauth2.enabled=true ma govpay.auth.oauth2.jwk-set-uri assente");
        }
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(oauth2.getJwkSetUri()).build();
        OAuth2TokenValidator<Jwt> validator = GovpayJwtValidatorFactory.createDefaultWithIssuerAudienceAndClaims(
                oauth2.getIssuer(), oauth2.getAudience(), oauth2.getClaimValidationRules());
        decoder.setJwtValidator(validator);
        return decoder;
    }

    @Bean
    @ConditionalOnMissingBean(GovpayJwtAuthenticationConverter.class)
    @ConditionalOnProperty(prefix = "govpay.auth.oauth2", name = "enabled")
    public GovpayJwtAuthenticationConverter govpayJwtAuthenticationConverter(
            GovpayAuthProperties properties,
            GovpayPrincipalLoader principalLoader) {
        return new GovpayJwtAuthenticationConverter(principalLoader, properties.getOauth2().getPrincipalClaimName());
    }

    @Bean
    @ConditionalOnMissingBean(BearerTokenProblemAuthenticationEntryPoint.class)
    @ConditionalOnProperty(prefix = "govpay.auth.oauth2", name = "enabled")
    public BearerTokenProblemAuthenticationEntryPoint bearerTokenProblemAuthenticationEntryPoint(
            GovpayAuthProperties properties,
            ObjectMapper objectMapper) {
        return new BearerTokenProblemAuthenticationEntryPoint(objectMapper, properties.getOauth2().getRealmName());
    }

    @Bean
    @ConditionalOnMissingBean(CorsConfigurationSource.class)
    @ConditionalOnProperty(prefix = "govpay.auth.cors", name = "enabled")
    public CorsConfigurationSource govpayCorsConfigurationSource(GovpayAuthProperties properties) {
        GovpayAuthProperties.Cors cors = properties.getCors();
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowCredentials(cors.isAllowCredentials());
        if (cors.isAllowAllOrigin()) {
            cfg.addAllowedOriginPattern("*");
        } else {
            cfg.setAllowedOrigins(cors.getAllowOrigins());
        }
        cfg.setAllowedHeaders(cors.getAllowHeaders());
        cfg.setAllowedMethods(cors.getAllowMethods());
        cfg.setExposedHeaders(cors.getExposeHeaders());
        cfg.setMaxAge(cors.getMaxAgeSeconds());
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration(cors.getPathPattern(), cfg);
        return source;
    }

    @Bean
    @Order(50)
    public SecurityFilterChain govpaySecurityFilterChain(
            HttpSecurity http,
            @Qualifier("problemAuthenticationEntryPoint") AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler,
            AuthTypeStampingFilter authTypeStampingFilter,
            ObjectProvider<JsonUsernamePasswordAuthenticationFilter> jsonLoginFilterProvider,
            ObjectProvider<HeaderPreAuthenticationFilter> headerFilterProvider,
            ObjectProvider<SslHeaderPreAuthenticationFilter> sslHeaderFilterProvider,
            ObjectProvider<ApiKeyAuthenticationFilter> apiKeyFilterProvider,
            ObjectProvider<SpidPreAuthenticationFilter> spidFilterProvider,
            ObjectProvider<SessionPreAuthenticationFilter> sessionFilterProvider,
            ObjectProvider<LdapAuthenticationFilter> ldapFilterProvider,
            ObjectProvider<JwtDecoder> jwtDecoderProvider,
            ObjectProvider<GovpayJwtAuthenticationConverter> jwtAuthenticationConverterProvider,
            ObjectProvider<BearerTokenProblemAuthenticationEntryPoint> bearerEntryPointProvider,
            ObjectProvider<CorsConfigurationSource> corsConfigurationSourceProvider,
            @Qualifier("basicUserDetailsService") ObjectProvider<UserDetailsService> basicUdsProvider,
            @Qualifier("sslUserDetailsService") ObjectProvider<UserDetailsService> sslUdsProvider,
            PasswordEncoder passwordEncoder,
            GovpayAuthProperties properties,
            AuthEventListener eventListener,
            ObjectMapper objectMapper) throws Exception {

        GovpayAuthProperties.Form form = properties.getForm();
        boolean formEnabled = form.isEnabled();
        boolean spidEnabled = properties.getSpid().isEnabled();
        // Sessione creata IF_REQUIRED solo per FORM e SPID. La chain SESSION
        // V1 era stateless: legge la sessione esistente, non ne crea.
        boolean sessionAware = formEnabled || spidEnabled;

        http.securityMatcher("/**")
                .exceptionHandling(eh -> eh
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .accessDeniedHandler(accessDeniedHandler));

        corsConfigurationSourceProvider.ifAvailable(src -> {
            try {
                http.cors(c -> c.configurationSource(src));
            } catch (Exception ex) {
                throw new IllegalStateException("CORS config failed", ex);
            }
        });

        configureAuthorization(http, properties.getPublicChain(), properties.getStaticResources());
        configureHeaders(http, properties.getHeaders());
        configureSession(http, sessionAware, objectMapper);
        configureCsrf(http, form, sessionAware);
        configureChainManagerAndBuiltins(http, properties, basicUdsProvider, sslUdsProvider,
                passwordEncoder, authenticationEntryPoint);
        // Logout abilitato per qualunque metodo session-based (FORM o SPID).
        configureSessionLogout(http, form, formEnabled || spidEnabled, eventListener);
        configureOauth2(http, properties.getOauth2(), jwtDecoderProvider, jwtAuthenticationConverterProvider,
                bearerEntryPointProvider, objectMapper);

        // Filter custom della libreria: posizionati prima/dopo Basic per ordine deterministico.
        jsonLoginFilterProvider.ifAvailable(f -> http.addFilterBefore(f, BasicAuthenticationFilter.class));
        apiKeyFilterProvider.ifAvailable(f -> http.addFilterBefore(f, BasicAuthenticationFilter.class));
        headerFilterProvider.ifAvailable(f -> http.addFilterBefore(f, BasicAuthenticationFilter.class));
        sslHeaderFilterProvider.ifAvailable(f -> http.addFilterBefore(f, BasicAuthenticationFilter.class));
        spidFilterProvider.ifAvailable(f -> http.addFilterBefore(f, BasicAuthenticationFilter.class));
        sessionFilterProvider.ifAvailable(f -> http.addFilterBefore(f, BasicAuthenticationFilter.class));
        // LDAP prima di BasicAuth: tenta LDAP-bind, su fallimento lascia il
        // fallback a BasicAuthenticationFilter (provider DAO).
        ldapFilterProvider.ifAvailable(f -> http.addFilterBefore(f, BasicAuthenticationFilter.class));
        http.addFilterAfter(authTypeStampingFilter, BasicAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Configura le regole di autorizzazione:
     * <ul>
     *   <li>Static resources (se {@code govpay.auth.static-resources.enabled}) → permitAll;</li>
     *   <li>Public chain rules (path + opzionalmente metodi HTTP) → permitAll;</li>
     *   <li>OPTIONS su {@code /**} → permitAll (CORS preflight, V1-aligned);</li>
     *   <li>{@code anyRequest().authenticated()}.</li>
     * </ul>
     */
    private static void configureAuthorization(HttpSecurity http,
                                               GovpayAuthProperties.PublicChain publicChain,
                                               GovpayAuthProperties.StaticResources staticResources) throws Exception {
        boolean publicEnabled = publicChain.isEnabled();
        java.util.List<GovpayAuthProperties.PermitAllRule> rules =
                publicEnabled ? publicChain.getPermitAllPaths() : java.util.List.of();
        java.util.List<String> staticPaths =
                staticResources.isEnabled() ? staticResources.getPermitAllPaths() : java.util.List.of();
        http.authorizeHttpRequests(a -> {
            // CORS preflight (V1: <intercept-url pattern="/**" access="permitAll" method="OPTIONS"/>).
            a.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll();
            for (String path : staticPaths) {
                a.requestMatchers(path).permitAll();
            }
            for (GovpayAuthProperties.PermitAllRule rule : rules) {
                if (rule.getMethods() == null || rule.getMethods().isEmpty()) {
                    a.requestMatchers(rule.getPath()).permitAll();
                } else {
                    for (String method : rule.getMethods()) {
                        a.requestMatchers(HttpMethod.valueOf(method.toUpperCase()), rule.getPath()).permitAll();
                    }
                }
            }
            a.anyRequest().authenticated();
        });
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
                                         boolean sessionAware,
                                         ObjectMapper objectMapper) throws Exception {
        if (sessionAware) {
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
                                      boolean sessionAware) throws Exception {
        if (!sessionAware) {
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

    /**
     * Logout per i metodi session-based (FORM e SPID). V1 aveva URL distinte
     * per chain ({@code /rs/form/v1/logout}, {@code /rs/spid/v1/logout}); V2
     * chain unica condivide {@code /auth/logout} per tutti i metodi che
     * gestiscono sessione.
     */
    private static void configureSessionLogout(HttpSecurity http,
                                               GovpayAuthProperties.Form form,
                                               boolean sessionLogoutEnabled,
                                               AuthEventListener eventListener) throws Exception {
        if (!sessionLogoutEnabled) {
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

    /**
     * Configura OAuth2 Resource Server (JWT) con decoder/validator V1-faithful,
     * converter SPI-based per il mapping principal → Utenza locale, entry point
     * problem+json con WWW-Authenticate Bearer, e optional logout handler OIDC.
     */
    private static void configureOauth2(HttpSecurity http,
                                        GovpayAuthProperties.Oauth2 oauth2,
                                        ObjectProvider<JwtDecoder> jwtDecoderProvider,
                                        ObjectProvider<GovpayJwtAuthenticationConverter> jwtAuthenticationConverterProvider,
                                        ObjectProvider<BearerTokenProblemAuthenticationEntryPoint> bearerEntryPointProvider,
                                        ObjectMapper objectMapper) throws Exception {
        if (!oauth2.isEnabled()) {
            return;
        }
        JwtDecoder decoder = jwtDecoderProvider.getIfAvailable();
        GovpayJwtAuthenticationConverter converter = jwtAuthenticationConverterProvider.getIfAvailable();
        BearerTokenProblemAuthenticationEntryPoint entryPoint = bearerEntryPointProvider.getIfAvailable();
        if (decoder == null || converter == null || entryPoint == null) {
            return;
        }
        http.oauth2ResourceServer(oauth -> oauth
                .authenticationEntryPoint(entryPoint)
                .jwt(jwt -> jwt
                        .decoder(decoder)
                        .jwtAuthenticationConverter(converter)));
        // Logout OAuth2 separato: solo se logoutUri/postLogoutRedirectUri configurati.
        if (oauth2.getLogoutUri() != null && !oauth2.getLogoutUri().isBlank()
                && oauth2.getPostLogoutRedirectUri() != null && !oauth2.getPostLogoutRedirectUri().isBlank()) {
            RequestMatcher matcher = PathPatternRequestMatcher.withDefaults()
                    .matcher(HttpMethod.POST, oauth2.getLogoutPath());
            http.logout(l -> l
                    .logoutRequestMatcher(matcher)
                    .logoutSuccessHandler(new Oauth2LogoutSuccessHandler(
                            oauth2.getLogoutUri(), oauth2.getPostLogoutRedirectUri(), objectMapper)));
        }
    }
}
