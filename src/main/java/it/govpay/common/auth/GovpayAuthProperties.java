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
    private final Method form = new Method();
    private final Method ssl = new Method();
    private final Method sslHeader = new Method();
    private final Method header = new Method();
    private final Method apiKey = new Method();
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

    public Method getForm() {
        return form;
    }

    public Method getSsl() {
        return ssl;
    }

    public Method getSslHeader() {
        return sslHeader;
    }

    public Method getHeader() {
        return header;
    }

    public Method getApiKey() {
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
