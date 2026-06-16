package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

class GovpayJwtValidatorsTest {

    private static Jwt buildJwt(Map<String, Object> claims) {
        return new Jwt(
                "token-value",
                Instant.now().minusSeconds(10),
                Instant.now().plusSeconds(60),
                Map.of("alg", "RS256"),
                claims);
    }

    @Test
    void issuerValidatorPassesWhenIssuerMatches() {
        GovpayJwtIssuerValidator validator = new GovpayJwtIssuerValidator("https://idp.example.com");
        OAuth2TokenValidatorResult result = validator.validate(
                buildJwt(Map.of("iss", "https://idp.example.com")));
        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void issuerValidatorFailsWhenIssuerMismatched() {
        GovpayJwtIssuerValidator validator = new GovpayJwtIssuerValidator("https://idp.example.com");
        OAuth2TokenValidatorResult result = validator.validate(
                buildJwt(Map.of("iss", "https://attacker.example.com")));
        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void issuerValidatorSkipsWhenEmpty() {
        GovpayJwtIssuerValidator validator = new GovpayJwtIssuerValidator("");
        assertThat(validator.validate(buildJwt(Map.of("sub", "alice"))).hasErrors()).isFalse();
    }

    @Test
    void audienceValidatorAcceptsString() {
        GovpayJwtAudienceValidator validator = new GovpayJwtAudienceValidator("api-backoffice");
        assertThat(validator.validate(buildJwt(Map.of("aud", "api-backoffice"))).hasErrors()).isFalse();
    }

    @Test
    void audienceValidatorAcceptsCollection() {
        GovpayJwtAudienceValidator validator = new GovpayJwtAudienceValidator("api-backoffice");
        assertThat(validator.validate(buildJwt(Map.of("aud", List.of("frontend", "api-backoffice")))).hasErrors())
                .isFalse();
    }

    @Test
    void audienceValidatorFailsWhenNotInCollection() {
        GovpayJwtAudienceValidator validator = new GovpayJwtAudienceValidator("api-backoffice");
        assertThat(validator.validate(buildJwt(Map.of("aud", List.of("frontend")))).hasErrors())
                .isTrue();
    }

    @Test
    void claimsValidatorMultipleRules() {
        GovpayJwtClaimsValidator validator = new GovpayJwtClaimsValidator(Map.of(
                "scope", List.of("read", "write"),
                "tenant", List.of("acme")));
        assertThat(validator.validate(
                buildJwt(Map.of("scope", "write", "tenant", "acme"))).hasErrors()).isFalse();
        assertThat(validator.validate(
                buildJwt(Map.of("scope", "delete", "tenant", "acme"))).hasErrors()).isTrue();
        assertThat(validator.validate(
                buildJwt(Map.of("scope", "read"))).hasErrors()).isTrue(); // tenant missing
    }

    @Test
    void claimsValidatorSkipsWhenRulesEmpty() {
        GovpayJwtClaimsValidator validator = new GovpayJwtClaimsValidator(Map.of());
        assertThat(validator.isSkipValidation()).isTrue();
        assertThat(validator.validate(buildJwt(Map.of("sub", "alice"))).hasErrors()).isFalse();
    }

    @Test
    void factoryComposesAllValidators() {
        OAuth2TokenValidator<Jwt> v = GovpayJwtValidatorFactory.createDefaultWithIssuerAudienceAndClaims(
                "https://idp", "api", Map.of("tenant", List.of("acme")));
        assertThat(v.validate(buildJwt(Map.of(
                "iss", "https://idp", "aud", "api", "tenant", "acme"))).hasErrors()).isFalse();
        assertThat(v.validate(buildJwt(Map.of(
                "iss", "https://attacker", "aud", "api", "tenant", "acme"))).hasErrors()).isTrue();
    }
}
