package it.govpay.common.auth;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;

/**
 * Factory per costruire validator JWT compositi.
 *
 * <p>4 metodi factory ({@code createDefaultWithIssuerAndAudience},
 * {@code createDefaultWithIssuerAudienceAndClaims},
 * {@code createDefaultWithClaims}, {@code createWithCustomValidators}). Tutti
 * i validator costruiti includono sempre {@link JwtTimestampValidator}.
 */
public final class GovpayJwtValidatorFactory {

    private GovpayJwtValidatorFactory() {
        // utility
    }

    public static OAuth2TokenValidator<Jwt> createDefaultWithIssuerAndAudience(String issuer, String audience) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtTimestampValidator());
        validators.add(new GovpayJwtIssuerValidator(issuer));
        validators.add(new GovpayJwtAudienceValidator(audience));
        return new DelegatingOAuth2TokenValidator<>(validators);
    }

    public static OAuth2TokenValidator<Jwt> createDefaultWithIssuerAudienceAndClaims(
            String issuer,
            String audience,
            Map<String, ? extends Collection<String>> claimValidationRules) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtTimestampValidator());
        validators.add(new GovpayJwtIssuerValidator(issuer));
        validators.add(new GovpayJwtAudienceValidator(audience));
        validators.add(new GovpayJwtClaimsValidator(claimValidationRules));
        return new DelegatingOAuth2TokenValidator<>(validators);
    }

    public static OAuth2TokenValidator<Jwt> createDefaultWithClaims(
            Map<String, ? extends Collection<String>> claimValidationRules) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtTimestampValidator());
        validators.add(new GovpayJwtClaimsValidator(claimValidationRules));
        return new DelegatingOAuth2TokenValidator<>(validators);
    }

    public static OAuth2TokenValidator<Jwt> createWithCustomValidators(
            List<OAuth2TokenValidator<Jwt>> customValidators) {
        List<OAuth2TokenValidator<Jwt>> validators = new ArrayList<>();
        validators.add(new JwtTimestampValidator());
        if (customValidators != null && !customValidators.isEmpty()) {
            validators.addAll(customValidators);
        }
        return new DelegatingOAuth2TokenValidator<>(validators);
    }
}
