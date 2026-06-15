package it.govpay.common.auth;

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
    private final Form form = new Form();
    private final Ssl ssl = new Ssl();
    private final SslHeader sslHeader = new SslHeader();
    private final Header header = new Header();
    private final ApiKey apiKey = new ApiKey();
    private final Method spid = new Method();
    private final Method session = new Method();
    private final Method oauth2 = new Method();
    private final Method publicChain = new Method();

    public Password getPassword() {
        return password;
    }

    public Method getBasic() {
        return basic;
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

    public Method getSpid() {
        return spid;
    }

    public Method getSession() {
        return session;
    }

    public Method getOauth2() {
        return oauth2;
    }

    /**
     * Mappata su property {@code govpay.auth.public.*}; il nome del getter
     * usa {@code publicChain} perche' {@code public} e' keyword Java.
     */
    public Method getPublicChain() {
        return publicChain;
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
     */
    public static class Header extends Method {

        /** Nome dell'header che porta il principal. */
        private String principalHeaderName = "X-Pre-Auth-User";

        public String getPrincipalHeaderName() {
            return principalHeaderName;
        }

        public void setPrincipalHeaderName(String principalHeaderName) {
            this.principalHeaderName = principalHeaderName;
        }
    }

    /**
     * Configurazione del metodo SSL_HEADER (certificato client SSL inoltrato
     * via header da reverse proxy / API gateway).
     *
     * <p>Versione semplificata rispetto a V1: si assume che l'header porti gia'
     * il subject DN pronto. Encoding base64/URL e replace caratteri sono
     * fuori scope; gateway che ne abbiano bisogno possono pre-decodificare
     * a monte oppure registrare un decoder custom.
     */
    public static class SslHeader extends Method {

        /** Nome dell'header che porta il subject DN del certificato. */
        private String principalHeaderName = "X-SSL-Client-S-Dn";

        public String getPrincipalHeaderName() {
            return principalHeaderName;
        }

        public void setPrincipalHeaderName(String principalHeaderName) {
            this.principalHeaderName = principalHeaderName;
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
