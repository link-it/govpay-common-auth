package it.govpay.common.auth;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

/**
 * Validator generico per claim multipli del JWT con lista di valori ammessi
 * per ciascun claim.
 *
 * <p>La mappa vuota disabilita la validazione; per ciascuna regola il claim deve
 * essere presente nel token e match contro almeno uno dei valori attesi
 * (gestisce String, Collection, array).
 */
public class GovpayJwtClaimsValidator implements OAuth2TokenValidator<Jwt> {

    private static final String ERROR_CODE_INVALID_CLAIM = "invalid_token";
    private static final Logger log = LoggerFactory.getLogger(GovpayJwtClaimsValidator.class);

    private final Map<String, Set<String>> claimValidationRules;
    private final boolean skipValidation;

    public GovpayJwtClaimsValidator(Map<String, ? extends Collection<String>> rules) {
        Assert.notNull(rules, "rules cannot be null");
        if (rules.isEmpty()) {
            this.skipValidation = true;
            this.claimValidationRules = Collections.emptyMap();
            log.warn("Nessuna regola di validazione claim fornita. Validazione disabilitata.");
            return;
        }
        Map<String, Set<String>> filtered = new HashMap<>();
        for (Map.Entry<String, ? extends Collection<String>> entry : rules.entrySet()) {
            String claimName = entry.getKey();
            Collection<String> expectedValues = entry.getValue();
            if (claimName == null || claimName.isEmpty()) {
                continue;
            }
            if (expectedValues == null || expectedValues.isEmpty()) {
                continue;
            }
            List<String> nonBlank = new ArrayList<>();
            for (String v : expectedValues) {
                if (v != null && !v.isBlank()) {
                    nonBlank.add(v);
                }
            }
            if (nonBlank.isEmpty()) {
                continue;
            }
            filtered.put(claimName, Set.copyOf(nonBlank));
        }
        this.claimValidationRules = filtered;
        this.skipValidation = filtered.isEmpty();
        if (skipValidation) {
            log.warn("Nessuna regola di validazione claim valida. Validazione disabilitata.");
        }
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        Assert.notNull(token, "token cannot be null");
        if (skipValidation) {
            return OAuth2TokenValidatorResult.success();
        }
        List<OAuth2Error> errors = new ArrayList<>();
        for (Map.Entry<String, Set<String>> entry : claimValidationRules.entrySet()) {
            String claimName = entry.getKey();
            Set<String> expected = entry.getValue();
            Object claimValue = token.getClaim(claimName);
            if (claimValue == null) {
                errors.add(new OAuth2Error(ERROR_CODE_INVALID_CLAIM,
                        "Il claim '" + claimName + "' e' assente nel token. Atteso: " + expected, null));
                continue;
            }
            if (!matches(claimValue, expected)) {
                errors.add(new OAuth2Error(ERROR_CODE_INVALID_CLAIM,
                        "Il claim '" + claimName + "' con valore '" + claimValue + "' non e' valido. Atteso: " + expected, null));
            }
        }
        if (!errors.isEmpty()) {
            return OAuth2TokenValidatorResult.failure(errors);
        }
        return OAuth2TokenValidatorResult.success();
    }

    private static boolean matches(Object claimValue, Set<String> expected) {
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
    }

    public Map<String, Set<String>> getClaimValidationRules() {
        return Collections.unmodifiableMap(claimValidationRules);
    }

    public boolean isSkipValidation() {
        return skipValidation;
    }
}
