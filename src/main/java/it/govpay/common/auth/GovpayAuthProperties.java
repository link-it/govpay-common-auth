package it.govpay.common.auth;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configurazione della libreria common-auth, prefisso {@code govpay.auth.*}.
 *
 * <p>Layout incrementale: in questo step (#2) sono definiti solo i flag di
 * abilitazione per ciascun {@link it.govpay.common.auth.spi.AuthType} e la
 * configurazione dell'encoder di password. Le sub-property specifiche di
 * ciascun metodo (path-pattern, rate-limit, login/logout URL, ...) vengono
 * aggiunte negli step successivi quando il filter corrispondente viene
 * portato dalla V1.
 */
@ConfigurationProperties("govpay.auth")
public class GovpayAuthProperties {

    private final Password password = new Password();
    private final Method basic = new Method();
    private final Ldap ldap = new Ldap();
    private final Form form = new Form();
    private final Ssl ssl = new Ssl();
    private final SslHeader sslHeader = new SslHeader();
    private final Header header = new Header();
    private final ApiKey apiKey = new ApiKey();
    private final Headers headers = new Headers();
    private final Firewall firewall = new Firewall();
    private final Cors cors = new Cors();
    private final StaticResources staticResources = new StaticResources();
    private final Spid spid = new Spid();
    private final Session session = new Session();
    private final Oauth2 oauth2 = new Oauth2();
    private final PublicChain publicChain = new PublicChain();

    public Password getPassword() {
        return password;
    }

    public Method getBasic() {
        return basic;
    }

    public Ldap getLdap() {
        return ldap;
    }

    public Form getForm() {
        return form;
    }

    public Ssl getSsl() {
        return ssl;
    }

    public SslHeader getSslHeader() {
        return sslHeader;
    }

    public Header getHeader() {
        return header;
    }

    public ApiKey getApiKey() {
        return apiKey;
    }

    public Spid getSpid() {
        return spid;
    }

    public Session getSession() {
        return session;
    }

    public Oauth2 getOauth2() {
        return oauth2;
    }

    /**
     * Mappata su property {@code govpay.auth.public.*}; il nome del getter
     * usa {@code publicChain} perche' {@code public} e' keyword Java.
     */
    public PublicChain getPublicChain() {
        return publicChain;
    }

    public Headers getHeaders() {
        return headers;
    }

    public Firewall getFirewall() {
        return firewall;
    }

    public Cors getCors() {
        return cors;
    }

    public StaticResources getStaticResources() {
        return staticResources;
    }

    /**
     * Configurazione comune a tutti i metodi di autenticazione: flag di
     * abilitazione. Le configurazioni specifiche (path-pattern, ...) saranno
     * aggiunte in sotto-classi negli step dedicati.
     */
    public static class Method {

        private boolean enabled = false;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    /**
     * Configurazione del metodo FORM (login JSON + sessione + CSRF cookie +
     * rate limit). Estende {@link Method} aggiungendo le path-property di
     * login/logout e il rate limiter sui tentativi falliti.
     */
    public static class Form extends Method {

        /**
         * URL del filter custom {@code JsonUsernamePasswordAuthenticationFilter}.
         * Spring Security mappa la POST su questo path per gestire il login.
         */
        private String loginPath = "/auth/login";

        /**
         * URL del {@code LogoutFilter} di Spring Security.
         */
        private String logoutPath = "/auth/logout";

        /**
         * Nome del cookie che porta il CSRF token verso il browser
         * (allineato Angular: {@code XSRF-TOKEN}).
         */
        private String csrfCookieName = "XSRF-TOKEN";

        /**
         * Nome dell'header con cui il browser rispedisce il CSRF token.
         */
        private String csrfHeaderName = "X-XSRF-TOKEN";

        private final RateLimit rateLimit = new RateLimit();

        public String getLoginPath() {
            return loginPath;
        }

        public void setLoginPath(String loginPath) {
            this.loginPath = loginPath;
        }

        public String getLogoutPath() {
            return logoutPath;
        }

        public void setLogoutPath(String logoutPath) {
            this.logoutPath = logoutPath;
        }

        public String getCsrfCookieName() {
            return csrfCookieName;
        }

        public void setCsrfCookieName(String csrfCookieName) {
            this.csrfCookieName = csrfCookieName;
        }

        public String getCsrfHeaderName() {
            return csrfHeaderName;
        }

        public void setCsrfHeaderName(String csrfHeaderName) {
            this.csrfHeaderName = csrfHeaderName;
        }

        public RateLimit getRateLimit() {
            return rateLimit;
        }
    }

    /**
     * Configurazione del metodo SSL (autenticazione mutua TLS con cert client).
     * Spring Security usa {@code X509AuthenticationFilter}.
     */
    public static class Ssl extends Method {

        /**
         * Regex applicata al subject del certificato per estrarne il principal.
         * Default V1: l'intero subject DN come principal.
         */
        private String subjectPrincipalRegex = "^(.*)$";

        public String getSubjectPrincipalRegex() {
            return subjectPrincipalRegex;
        }

        public void setSubjectPrincipalRegex(String subjectPrincipalRegex) {
            this.subjectPrincipalRegex = subjectPrincipalRegex;
        }
    }

    /**
     * Configurazione del metodo HEADER (principal in header HTTP, tipico di
     * reverse proxy che ha gia' autenticato l'utente a monte).
     *
     * <p>V1-aligned: la property e' una lista di nomi header. Il filter
     * itera in ordine, prende il valore del primo header non-vuoto presente
     * sulla request.
     */
    public static class Header extends Method {

        /**
         * Nomi degli header da consultare in ordine. Il primo non-null/non-blank
         * fornisce il principal. Replica V1 {@code getAutenticazioneHeaderNomeHeaderPrincipal()}
         * che ritornava una {@code List<String>}.
         */
        private List<String> principalHeaderNames = new ArrayList<>(List.of("X-Pre-Auth-User"));

        public List<String> getPrincipalHeaderNames() {
            return principalHeaderNames;
        }

        public void setPrincipalHeaderNames(List<String> principalHeaderNames) {
            this.principalHeaderNames = principalHeaderNames;
        }
    }

    /**
     * Configurazione del metodo SSL_HEADER (certificato client SSL inoltrato
     * via header da reverse proxy / API gateway).
     *
     * <p>Replica fedelmente la pipeline V1 di {@code SSLHeaderPreAuthFilter}:
     * replace caratteri (per gestire i caratteri di escape introdotti dai
     * proxy come {@code \t} al posto di {@code \n}) + try-fallback decoding
     * (URL → Base64 → Hex) + parsing X.509 + estrazione subject DN in formato
     * RFC 2253 (= {@code X500Principal.toString()}, identico a V1).
     */
    public static class SslHeader extends Method {

        /** Nome dell'header che porta il certificato (o subject DN gia' pronto). */
        private String principalHeaderName = "X-SSL-Client-Cert";

        /** Se true, URL-decodifica il contenuto dell'header prima di parsarlo. */
        private boolean urlDecode = false;

        /** Se true, base64-decodifica il contenuto dell'header prima di parsarlo. */
        private boolean base64Decode = false;

        /**
         * Se true, hex-decodifica il contenuto dell'header prima di parsarlo.
         * Replica per fedelta' V1, dove il branch hex era opzionale ma supportato.
         */
        private boolean hexDecode = false;

        /**
         * Se true, applica la sostituzione di caratteri sul body PEM
         * (protezione dei marker BEGIN/END inclusa) prima del decoding.
         * Caso d'uso: nginx con {@code $ssl_client_escaped_cert} che sostituisce
         * le newline con tab.
         */
        private boolean replaceCharactersEnabled = false;

        /**
         * Carattere/i da sostituire nel body PEM. Default V1: {@code \t} (tab).
         * Le stringhe letterali {@code \t}, {@code \r}, {@code \n}, {@code \r\n},
         * {@code \s} vengono tradotte nel rispettivo carattere reale (compat V1).
         */
        private String replaceSource;

        /**
         * Carattere/i di destinazione. Default V1: {@code \n} (newline).
         * Stesso trattamento delle stringhe letterali di {@code replaceSource}.
         */
        private String replaceDest;

        public String getPrincipalHeaderName() {
            return principalHeaderName;
        }

        public void setPrincipalHeaderName(String principalHeaderName) {
            this.principalHeaderName = principalHeaderName;
        }

        public boolean isUrlDecode() {
            return urlDecode;
        }

        public void setUrlDecode(boolean urlDecode) {
            this.urlDecode = urlDecode;
        }

        public boolean isBase64Decode() {
            return base64Decode;
        }

        public void setBase64Decode(boolean base64Decode) {
            this.base64Decode = base64Decode;
        }

        public boolean isHexDecode() {
            return hexDecode;
        }

        public void setHexDecode(boolean hexDecode) {
            this.hexDecode = hexDecode;
        }

        public boolean isReplaceCharactersEnabled() {
            return replaceCharactersEnabled;
        }

        public void setReplaceCharactersEnabled(boolean replaceCharactersEnabled) {
            this.replaceCharactersEnabled = replaceCharactersEnabled;
        }

        public String getReplaceSource() {
            return replaceSource;
        }

        public void setReplaceSource(String replaceSource) {
            this.replaceSource = replaceSource;
        }

        public String getReplaceDest() {
            return replaceDest;
        }

        public void setReplaceDest(String replaceDest) {
            this.replaceDest = replaceDest;
        }
    }

    /**
     * Configurazione del metodo API_KEY (coppia id/key in header HTTP,
     * gestita come Basic-like flow internamente).
     */
    public static class ApiKey extends Method {

        /** Nome dell'header che porta l'ID applicazione. */
        private String idHeaderName = "X-Govpay-API-ID";

        /** Nome dell'header che porta la chiave applicazione. */
        private String keyHeaderName = "X-Govpay-API-Key";

        public String getIdHeaderName() {
            return idHeaderName;
        }

        public void setIdHeaderName(String idHeaderName) {
            this.idHeaderName = idHeaderName;
        }

        public String getKeyHeaderName() {
            return keyHeaderName;
        }

        public void setKeyHeaderName(String keyHeaderName) {
            this.keyHeaderName = keyHeaderName;
        }
    }

    /**
     * Configurazione del rate-limiter per i tentativi falliti di login.
     */
    public static class RateLimit {

        /** Numero massimo di tentativi falliti per IP nella finestra. */
        private int attempts = 5;

        /** Durata della finestra sliding (in minuti) per il conteggio. */
        private int windowMinutes = 15;

        public int getAttempts() {
            return attempts;
        }

        public void setAttempts(int attempts) {
            this.attempts = attempts;
        }

        public int getWindowMinutes() {
            return windowMinutes;
        }

        public void setWindowMinutes(int windowMinutes) {
            this.windowMinutes = windowMinutes;
        }
    }

    /**
     * Configurazione del metodo LDAP (verifica credenziali Basic Auth via
     * server LDAP esterno, mapping a Utenza locale via SPI).
     *
     * <p>Porting V1 della sezione {@code BASIC_LDAP_PROVIDER} dello security
     * XML. Tutte le property sono obbligatorie quando LDAP e' abilitato
     * (salvo {@code managerDn}/{@code managerPassword}, opzionali se l'utente
     * puo' fare bind diretto).
     */
    public static class Ldap extends Method {

        /** URL del server LDAP (es. {@code ldap://ldap.example.com:389/dc=example,dc=com}). */
        private String url;

        /** DN del manager per il bind di lookup. Opzionale. */
        private String managerDn;

        /** Password del manager. Obbligatoria se {@code managerDn} settato. */
        private String managerPassword;

        /** Pattern del DN utente per il bind diretto, es. {@code uid={0},ou=people}. */
        private String userDnPattern;

        /** Filtro LDAP per la ricerca utenti, es. {@code (uid={0})}. */
        private String userSearchFilter;

        /** Base di ricerca utenti, es. {@code ou=people}. */
        private String userSearchBase;

        /** Base di ricerca gruppi, es. {@code ou=groups}. */
        private String groupSearchBase = "";

        /** Filtro LDAP per la ricerca gruppi, default {@code (uniqueMember={0})}. */
        private String groupSearchFilter = "(uniqueMember={0})";

        /** Nome dell'attributo password nel directory. Default {@code userPassword}. */
        private String passwordAttributeName = "userPassword";

        /** Prefisso ruoli, default {@code ROLE_}. */
        private String rolePrefix = "ROLE_";

        /** Se true, i ruoli LDAP vengono convertiti in upper-case. */
        private boolean convertToUpperCase = true;

        public String getUrl() { return url; }
        public void setUrl(String url) { this.url = url; }
        public String getManagerDn() { return managerDn; }
        public void setManagerDn(String managerDn) { this.managerDn = managerDn; }
        public String getManagerPassword() { return managerPassword; }
        public void setManagerPassword(String managerPassword) { this.managerPassword = managerPassword; }
        public String getUserDnPattern() { return userDnPattern; }
        public void setUserDnPattern(String userDnPattern) { this.userDnPattern = userDnPattern; }
        public String getUserSearchFilter() { return userSearchFilter; }
        public void setUserSearchFilter(String userSearchFilter) { this.userSearchFilter = userSearchFilter; }
        public String getUserSearchBase() { return userSearchBase; }
        public void setUserSearchBase(String userSearchBase) { this.userSearchBase = userSearchBase; }
        public String getGroupSearchBase() { return groupSearchBase; }
        public void setGroupSearchBase(String groupSearchBase) { this.groupSearchBase = groupSearchBase; }
        public String getGroupSearchFilter() { return groupSearchFilter; }
        public void setGroupSearchFilter(String groupSearchFilter) { this.groupSearchFilter = groupSearchFilter; }
        public String getPasswordAttributeName() { return passwordAttributeName; }
        public void setPasswordAttributeName(String passwordAttributeName) { this.passwordAttributeName = passwordAttributeName; }
        public String getRolePrefix() { return rolePrefix; }
        public void setRolePrefix(String rolePrefix) { this.rolePrefix = rolePrefix; }
        public boolean isConvertToUpperCase() { return convertToUpperCase; }
        public void setConvertToUpperCase(boolean convertToUpperCase) { this.convertToUpperCase = convertToUpperCase; }
    }

    /**
     * Configurazione del metodo OAUTH2 (resource server JWT, autorizzazione
     * delegata a Identity Provider esterno).
     *
     * <p>Porting V1 di {@code OAUTH2_PKCE} dello security XML. Il token
     * Bearer viene decodificato via {@code NimbusJwtDecoder} (JWK Set URI
     * configurabile), validato tramite issuer / audience / claim custom, e
     * il principal viene risolto via SPI {@link it.govpay.common.auth.spi.GovpayPrincipalLoader}
     * con {@link it.govpay.common.auth.spi.AuthType#OAUTH2}.
     */
    public static class Oauth2 extends Method {

        /** JWK Set URI da cui ricavare le chiavi pubbliche dell'IdP. Obbligatorio se OAUTH2 abilitato. */
        private String jwkSetUri;

        /** Issuer atteso nel claim {@code iss}. Empty/null disabilita il check. */
        private String issuer = "";

        /** Audience atteso nel claim {@code aud}. Empty/null disabilita il check. */
        private String audience = "";

        /**
         * Nome del claim da cui estrarre il principal. Default {@code sub}.
         * Supporta lista CSV per fallback (es. {@code "preferred_username,sub"}).
         */
        private String principalClaimName = "sub";

        /**
         * Regole di validazione su claim aggiuntivi: key = nome claim,
         * value = lista di valori ammessi. Replica V1 {@code oauth2ClaimValidationRules}.
         */
        private Map<String, List<String>> claimValidationRules = new HashMap<>();

        /** Realm per l'header {@code WWW-Authenticate: Bearer realm="..."}. */
        private String realmName;

        /**
         * URI di logout dell'IdP OIDC. Se settato + {@code postLogoutRedirectUri}
         * settato, l'handler logout costruisce e ritorna l'URL di logout completo.
         */
        private String logoutUri;

        /** URI di post-logout redirect (parametro {@code post_logout_redirect_uri}). */
        private String postLogoutRedirectUri;

        /** Path della logout OAuth2. Default {@code /auth/oauth2/logout}. */
        private String logoutPath = "/auth/oauth2/logout";

        public String getJwkSetUri() { return jwkSetUri; }
        public void setJwkSetUri(String jwkSetUri) { this.jwkSetUri = jwkSetUri; }
        public String getIssuer() { return issuer; }
        public void setIssuer(String issuer) { this.issuer = issuer; }
        public String getAudience() { return audience; }
        public void setAudience(String audience) { this.audience = audience; }
        public String getPrincipalClaimName() { return principalClaimName; }
        public void setPrincipalClaimName(String principalClaimName) { this.principalClaimName = principalClaimName; }
        public Map<String, List<String>> getClaimValidationRules() { return claimValidationRules; }
        public void setClaimValidationRules(Map<String, List<String>> claimValidationRules) { this.claimValidationRules = claimValidationRules; }
        public String getRealmName() { return realmName; }
        public void setRealmName(String realmName) { this.realmName = realmName; }
        public String getLogoutUri() { return logoutUri; }
        public void setLogoutUri(String logoutUri) { this.logoutUri = logoutUri; }
        public String getPostLogoutRedirectUri() { return postLogoutRedirectUri; }
        public void setPostLogoutRedirectUri(String postLogoutRedirectUri) { this.postLogoutRedirectUri = postLogoutRedirectUri; }
        public String getLogoutPath() { return logoutPath; }
        public void setLogoutPath(String logoutPath) { this.logoutPath = logoutPath; }
    }

    /**
     * Configurazione CORS V2 modernizzata. Sostituisce {@code OriginFilter}
     * di V1 (che si appoggiava a openspcoop2 {@code AbstractCORSFilter}) con
     * {@code CorsConfigurationSource} di Spring nativo.
     *
     * <p>Property con prefisso {@code govpay.auth.cors.*}. Quando
     * {@code enabled=true}, la chain registra una {@code CorsConfigurationSource}
     * e i preflight OPTIONS vengono gestiti automaticamente da Spring Security.
     */
    public static class Cors {

        private boolean enabled = false;

        /** Pattern URL su cui applicare CORS. Default {@code /**}. */
        private String pathPattern = "/**";

        /** Se true, espone tutti gli origin via {@code addAllowedOriginPattern("*")}. */
        private boolean allowAllOrigin = false;

        /** Lista esplicita di origin consentiti. Ignorata se {@code allowAllOrigin=true}. */
        private List<String> allowOrigins = new ArrayList<>();

        /** Header consentiti nelle request. Default {@code *}. */
        private List<String> allowHeaders = new ArrayList<>(List.of("*"));

        /** Metodi HTTP consentiti. Default {@code GET,POST,PUT,PATCH,DELETE,OPTIONS}. */
        private List<String> allowMethods = new ArrayList<>(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));

        /** Header esposti al browser via {@code Access-Control-Expose-Headers}. */
        private List<String> exposeHeaders = new ArrayList<>();

        /** {@code Access-Control-Allow-Credentials}. */
        private boolean allowCredentials = false;

        /** Max age in secondi della preflight cache. */
        private long maxAgeSeconds = 1800L;

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public String getPathPattern() { return pathPattern; }
        public void setPathPattern(String pathPattern) { this.pathPattern = pathPattern; }
        public boolean isAllowAllOrigin() { return allowAllOrigin; }
        public void setAllowAllOrigin(boolean allowAllOrigin) { this.allowAllOrigin = allowAllOrigin; }
        public List<String> getAllowOrigins() { return allowOrigins; }
        public void setAllowOrigins(List<String> allowOrigins) { this.allowOrigins = allowOrigins; }
        public List<String> getAllowHeaders() { return allowHeaders; }
        public void setAllowHeaders(List<String> allowHeaders) { this.allowHeaders = allowHeaders; }
        public List<String> getAllowMethods() { return allowMethods; }
        public void setAllowMethods(List<String> allowMethods) { this.allowMethods = allowMethods; }
        public List<String> getExposeHeaders() { return exposeHeaders; }
        public void setExposeHeaders(List<String> exposeHeaders) { this.exposeHeaders = exposeHeaders; }
        public boolean isAllowCredentials() { return allowCredentials; }
        public void setAllowCredentials(boolean allowCredentials) { this.allowCredentials = allowCredentials; }
        public long getMaxAgeSeconds() { return maxAgeSeconds; }
        public void setMaxAgeSeconds(long maxAgeSeconds) { this.maxAgeSeconds = maxAgeSeconds; }
    }

    /**
     * Configurazione default per le risorse statiche.
     *
     * <p>V1 catch-all chain permitteva esplicitamente {@code /index.html},
     * {@code /*.png}, {@code /*.css}, {@code /*.js}, ecc. per servire
     * Swagger UI dello stesso WAR. V2 librerizza il pattern: quando
     * {@code enabled=true}, i path elencati sono permitAll automatici.
     */
    public static class StaticResources {

        private boolean enabled = true;

        /** Path Spring pattern delle risorse statiche permitAll. */
        private List<String> permitAllPaths = new ArrayList<>(List.of(
                "/index.html",
                "/favicon.ico",
                "/*.png",
                "/*.css",
                "/*.css.map",
                "/*.js",
                "/*.js.map",
                "/webjars/**",
                "/static/**"));

        public boolean isEnabled() { return enabled; }
        public void setEnabled(boolean enabled) { this.enabled = enabled; }
        public List<String> getPermitAllPaths() { return permitAllPaths; }
        public void setPermitAllPaths(List<String> permitAllPaths) { this.permitAllPaths = permitAllPaths; }
    }

    /**
     * Configurazione del metodo SPID (principal estratto da header HTTP
     * popolato dall'Identity Provider SPID / shibboleth-proxy upstream).
     */
    public static class Spid extends Method {

        /**
         * Nome dell'header che porta il principal SPID. V1 obbligatorio
         * (property {@code it.govpay.autenticazioneSPID.nomeHeaderPrincipal}),
         * nessun default convenzionale. Se SPID e' abilitato e questo valore
         * e' null/blank, il bean del filter fallisce in costruzione.
         */
        private String principalHeaderName;

        /**
         * Prefisso convenzionale del valore dell'header da strippare per
         * ottenere il codice fiscale puro. Default V1: {@code "TINIT-"}.
         * Impostare a stringa vuota per disabilitare lo strip.
         */
        private String tinitPrefix = "TINIT-";

        public String getPrincipalHeaderName() {
            return principalHeaderName;
        }

        public void setPrincipalHeaderName(String principalHeaderName) {
            this.principalHeaderName = principalHeaderName;
        }

        public String getTinitPrefix() {
            return tinitPrefix;
        }

        public void setTinitPrefix(String tinitPrefix) {
            this.tinitPrefix = tinitPrefix;
        }
    }

    /**
     * Configurazione del metodo SESSION (principal letto da attributo della
     * {@link jakarta.servlet.http.HttpSession}, popolato a monte da un altro
     * filter/controller).
     */
    public static class Session extends Method {

        /**
         * Nome dell'attributo della sessione che porta il principal.
         * Default V1: {@code "GP_PRINCIPAL"} (costante
         * {@code AuthorizationManager.SESSION_PRINCIPAL_ATTRIBUTE_NAME}).
         */
        private String sessionPrincipalAttributeName = "GP_PRINCIPAL";

        public String getSessionPrincipalAttributeName() {
            return sessionPrincipalAttributeName;
        }

        public void setSessionPrincipalAttributeName(String sessionPrincipalAttributeName) {
            this.sessionPrincipalAttributeName = sessionPrincipalAttributeName;
        }
    }

    /**
     * Configurazione della chain PUBLIC (anonymous + permitAll su path
     * specifici).
     *
     * <p>In V1 era una chain separata {@code /rs/public/v1/**} con
     * {@code AnonymousAuthenticationFilter} + {@code intercept-url permitAll}
     * sui path consentiti. In V2 chain unica: i path elencati qui sono
     * esentati dal {@code authenticated()} globale.
     */
    public static class PublicChain extends Method {

        /**
         * Regole permitAll: path + opzionalmente metodi HTTP. Default lista
         * vuota: il consumer la riempie con i propri endpoint
         * (es. {@code /info}, {@code /actuator/health/liveness}).
         *
         * <p>V1-aligned: replica {@code <intercept-url pattern="..." method="GET"/>}
         * tramite {@link PermitAllRule#methods}.
         *
         * <p><b>Anonymous principal V1 non portato</b>: V1 estendeva
         * {@code AnonymousAuthenticationFilter} di Spring con un nome
         * specifico {@code "GovPay_API_Backoffice_Utenza_Anonima"} e caricava
         * il principal da {@code AutenticazioneUtenzeAnonimeDAO} (utenza
         * anonima con apiName=API_PAGAMONTO, authType=PUBLIC). Questa logica
         * dipende dal data layer del consumer (V1: tabella utenze locale) e
         * V2 la demanda al consumer tramite il proprio
         * {@code @Component AnonymousAuthenticationFilter} custom se serve.
         * La libreria si limita a permitAll dei path elencati; il principal
         * anonimo resta quello di default di Spring ({@code "anonymousUser"}
         * con {@code ROLE_ANONYMOUS}).
         */
        private List<PermitAllRule> permitAllPaths = new ArrayList<>();

        public List<PermitAllRule> getPermitAllPaths() {
            return permitAllPaths;
        }

        public void setPermitAllPaths(List<PermitAllRule> permitAllPaths) {
            this.permitAllPaths = permitAllPaths;
        }
    }

    /**
     * Regola di permitAll: pattern path + opzionalmente lista di metodi HTTP.
     * Se {@link #methods} e' vuota o null, la regola vale per tutti i verbi.
     */
    public static class PermitAllRule {

        private String path;
        private List<String> methods = new ArrayList<>();

        public String getPath() {
            return path;
        }

        public void setPath(String path) {
            this.path = path;
        }

        public List<String> getMethods() {
            return methods;
        }

        public void setMethods(List<String> methods) {
            this.methods = methods;
        }
    }

    /**
     * Configurazione degli header HTTP di sicurezza sulle response della chain.
     *
     * <p>Default V2-modern: tutti abilitati (Spring Security 7 default).
     * V1 li disabilitava esplicitamente su tutte le chain attive
     * ({@code basic}, {@code ssl}, {@code form}): chi vuole rispettare V1 al
     * 100% imposta i tre flag a {@code false}.
     */
    public static class Headers {

        /** Se true, manda {@code X-Content-Type-Options: nosniff}. */
        private boolean contentTypeOptionsEnabled = true;

        /** Se true, manda {@code X-Frame-Options: DENY}. */
        private boolean frameOptionsEnabled = true;

        /** Se true, manda {@code X-XSS-Protection}. */
        private boolean xssProtectionEnabled = true;

        public boolean isContentTypeOptionsEnabled() {
            return contentTypeOptionsEnabled;
        }

        public void setContentTypeOptionsEnabled(boolean contentTypeOptionsEnabled) {
            this.contentTypeOptionsEnabled = contentTypeOptionsEnabled;
        }

        public boolean isFrameOptionsEnabled() {
            return frameOptionsEnabled;
        }

        public void setFrameOptionsEnabled(boolean frameOptionsEnabled) {
            this.frameOptionsEnabled = frameOptionsEnabled;
        }

        public boolean isXssProtectionEnabled() {
            return xssProtectionEnabled;
        }

        public void setXssProtectionEnabled(boolean xssProtectionEnabled) {
            this.xssProtectionEnabled = xssProtectionEnabled;
        }
    }

    /**
     * Configurazione di {@code StrictHttpFirewall} di Spring Security.
     *
     * <p>Default V1-aligned: {@code allowUrlEncodedSlash=true},
     * {@code allowUrlEncodedPercent=true}. Necessario per gli identificativi
     * pagopa che contengono {@code /} (e quindi {@code %2F} encoded) nei
     * path REST.
     */
    public static class Firewall {

        /** Replica V1: {@code allowUrlEncodedSlash="true"}. */
        private boolean allowUrlEncodedSlash = true;

        /** Replica V1: {@code allowUrlEncodedPercent="true"}. */
        private boolean allowUrlEncodedPercent = true;

        public boolean isAllowUrlEncodedSlash() {
            return allowUrlEncodedSlash;
        }

        public void setAllowUrlEncodedSlash(boolean allowUrlEncodedSlash) {
            this.allowUrlEncodedSlash = allowUrlEncodedSlash;
        }

        public boolean isAllowUrlEncodedPercent() {
            return allowUrlEncodedPercent;
        }

        public void setAllowUrlEncodedPercent(boolean allowUrlEncodedPercent) {
            this.allowUrlEncodedPercent = allowUrlEncodedPercent;
        }
    }

    /**
     * Configurazione del {@link GovpayPasswordEncoder}.
     */
    public static class Password {

        /**
         * Se {@code true}, le password legacy con prefisso {@code $1$} (MD5
         * Unix crypt) sono ancora accettate in lettura. Disabilitare quando
         * il deploy garantisce che tutte le utenze sono state ricifrate in
         * {@code $6$} (SHA-512 Unix crypt).
         */
        private boolean md5FallbackEnabled = true;

        public boolean isMd5FallbackEnabled() {
            return md5FallbackEnabled;
        }

        public void setMd5FallbackEnabled(boolean md5FallbackEnabled) {
            this.md5FallbackEnabled = md5FallbackEnabled;
        }
    }
}
