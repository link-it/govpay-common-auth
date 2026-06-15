package it.govpay.common.auth;

import java.util.ArrayList;
import java.util.List;

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
    private final Headers headers = new Headers();
    private final Firewall firewall = new Firewall();
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

    public Headers getHeaders() {
        return headers;
    }

    public Firewall getFirewall() {
        return firewall;
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
