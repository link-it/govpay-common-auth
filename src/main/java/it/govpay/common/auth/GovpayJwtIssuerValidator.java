package it.govpay.common.auth;

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
 * Validator per il claim {@code iss} del JWT.
 *
 * <p>Se {@code issuer} e' null/empty il check e' disabilitato (success); altrimenti
 * il claim {@code iss} deve essere esattamente uguale al valore configurato.
 */
public class GovpayJwtIssuerValidator implements OAuth2TokenValidator<Jwt> {

    private static final Logger log = LoggerFactory.getLogger(GovpayJwtIssuerValidator.class);

    private final boolean skipCheck;
    private final JwtClaimValidator<Object> validator;

    public GovpayJwtIssuerValidator(String issuer) {
        if (issuer == null || issuer.isEmpty()) {
            this.skipCheck = true;
            log.warn("Controllo Issuer disabilitato.");
            this.validator = null;
        } else {
            this.skipCheck = false;
            Predicate<Object> testClaimValue = claimValue -> claimValue != null && issuer.equals(claimValue.toString());
            this.validator = new JwtClaimValidator<>(JwtClaimNames.ISS, testClaimValue);
        }
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
