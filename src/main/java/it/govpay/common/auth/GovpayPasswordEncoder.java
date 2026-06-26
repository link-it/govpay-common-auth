package it.govpay.common.auth;

import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.digest.Md5Crypt;
import org.apache.commons.codec.digest.Sha2Crypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * {@link PasswordEncoder} coerente con la cifratura usata da GovPay
 * (SHA-512 Unix crypt, {@code $6$<salt>$<hash>}).
 *
 * <p>In lettura supporta anche il formato legacy MD5 Unix crypt
 * ({@code $1$<salt>$<hash>}) come fallback, controllato dal flag passato al
 * costruttore. Quando lo si disattiva le password {@code $1$} vengono
 * rifiutate (es. dopo che tutte le utenze sono state ricifrate in {@code $6$}).
 */
public class GovpayPasswordEncoder implements PasswordEncoder {

    private static final Logger log = LoggerFactory.getLogger(GovpayPasswordEncoder.class);

    static final String SHA512_PREFIX = "$6$";
    static final String MD5_PREFIX = "$1$";
    private static final int MD5_SALT_END_INDEX = 11; // "$1$" + 8 char salt

    private final boolean md5FallbackEnabled;

    public GovpayPasswordEncoder(boolean md5FallbackEnabled) {
        this.md5FallbackEnabled = md5FallbackEnabled;
    }

    @Override
    public String encode(CharSequence rawPassword) {
        if (rawPassword == null) {
            return null;
        }
        return Sha2Crypt.sha512Crypt(rawPassword.toString().getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (rawPassword == null || encodedPassword == null || encodedPassword.isBlank()) {
            return false;
        }
        if (encodedPassword.startsWith(SHA512_PREFIX)) {
            return matchesSha512(rawPassword.toString(), encodedPassword);
        }
        if (encodedPassword.startsWith(MD5_PREFIX)) {
            if (!md5FallbackEnabled) {
                log.warn("MD5 password hash incontrato ma fallback disabilitato: la verifica fallisce.");
                return false;
            }
            return matchesMd5(rawPassword.toString(), encodedPassword);
        }
        log.warn("Prefisso hash password non riconosciuto: la verifica fallisce.");
        return false;
    }

    private static boolean matchesSha512(String rawPassword, String encodedPassword) {
        String recomputed = Sha2Crypt.sha512Crypt(rawPassword.getBytes(StandardCharsets.UTF_8), encodedPassword);
        return recomputed.equals(encodedPassword);
    }

    private static boolean matchesMd5(String rawPassword, String encodedPassword) {
        if (encodedPassword.length() < MD5_SALT_END_INDEX) {
            return false;
        }
        String saltSpec = encodedPassword.substring(0, MD5_SALT_END_INDEX);
        String recomputed = Md5Crypt.md5Crypt(rawPassword.getBytes(StandardCharsets.UTF_8), saltSpec);
        return recomputed.equals(encodedPassword);
    }
}
