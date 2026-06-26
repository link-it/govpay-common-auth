package it.govpay.common.auth;

import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Set;
import java.util.function.Predicate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.util.Assert;

/**
 * Validator per il claim {@code aud} del JWT.
 *
 * <p>Gestisce {@code aud} come stringa singola, {@code Collection}, o array.
 * Audience null/empty disabilita il check.
 */
public class GovpayJwtAudienceValidator implements OAuth2TokenValidator<Jwt> {

    private static final Logger log = LoggerFactory.getLogger(GovpayJwtAudienceValidator.class);

    private final boolean skipCheck;
    private final JwtClaimValidator<Object> validator;

    public GovpayJwtAudienceValidator(String audience) {
        if (audience == null || audience.isEmpty()) {
            this.skipCheck = true;
            log.warn("Controllo Audience disabilitato.");
            this.validator = null;
        } else {
            this.skipCheck = false;
            Predicate<Object> testClaimValue = createPredicate(audience);
            this.validator = new JwtClaimValidator<>(JwtClaimNames.AUD, testClaimValue);
        }
    }

    private static Predicate<Object> createPredicate(String audience) {
        Set<String> expected = Set.of(audience);
        return claimValue -> {
            if (claimValue == null) return false;
            if (claimValue instanceof String s) {
                return expected.contains(s);
            }
            if (claimValue instanceof Collection<?> col) {
                for (Object e : col) {
                    if (e != null && expected.contains(e.toString())) return true;
                }
                return false;
            }
            if (claimValue.getClass().isArray()) {
                int len = Array.getLength(claimValue);
                for (int i = 0; i < len; i++) {
                    Object e = Array.get(claimValue, i);
                    if (e != null && expected.contains(e.toString())) return true;
                }
                return false;
            }
            return expected.contains(claimValue.toString());
        };
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        Assert.notNull(token, "token cannot be null");
        if (skipCheck) {
            return OAuth2TokenValidatorResult.success();
        }
        return validator.validate(token);
    }
}
