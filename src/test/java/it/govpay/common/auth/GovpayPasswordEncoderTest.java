package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.digest.Md5Crypt;
import org.apache.commons.codec.digest.Sha2Crypt;
import org.junit.jupiter.api.Test;

class GovpayPasswordEncoderTest {

    private static final String RAW_PASSWORD = "super-secret-pwd-1234";

    private final GovpayPasswordEncoder encoderWithMd5Fallback = new GovpayPasswordEncoder(true);
    private final GovpayPasswordEncoder encoderWithoutMd5Fallback = new GovpayPasswordEncoder(false);

    @Test
    void encodeProducesSha512UnixCrypt() {
        String encoded = encoderWithMd5Fallback.encode(RAW_PASSWORD);

        assertThat(encoded).startsWith(GovpayPasswordEncoder.SHA512_PREFIX);
        assertThat(encoderWithMd5Fallback.matches(RAW_PASSWORD, encoded)).isTrue();
    }

    @Test
    void matchesWrongPasswordOnSha512() {
        String encoded = encoderWithMd5Fallback.encode(RAW_PASSWORD);

        assertThat(encoderWithMd5Fallback.matches("wrong", encoded)).isFalse();
    }

    @Test
    void matchesLegacyMd5WhenFallbackEnabled() {
        String md5Encoded = Md5Crypt.md5Crypt(RAW_PASSWORD.getBytes(StandardCharsets.UTF_8));
        assertThat(md5Encoded).startsWith(GovpayPasswordEncoder.MD5_PREFIX);

        assertThat(encoderWithMd5Fallback.matches(RAW_PASSWORD, md5Encoded)).isTrue();
        assertThat(encoderWithMd5Fallback.matches("wrong", md5Encoded)).isFalse();
    }

    @Test
    void rejectsLegacyMd5WhenFallbackDisabled() {
        String md5Encoded = Md5Crypt.md5Crypt(RAW_PASSWORD.getBytes(StandardCharsets.UTF_8));

        assertThat(encoderWithoutMd5Fallback.matches(RAW_PASSWORD, md5Encoded)).isFalse();
    }

    @Test
    void matchesPreEncodedSha512() {
        String preEncoded = Sha2Crypt.sha512Crypt(RAW_PASSWORD.getBytes(StandardCharsets.UTF_8));

        assertThat(encoderWithMd5Fallback.matches(RAW_PASSWORD, preEncoded)).isTrue();
    }

    @Test
    void rejectsNullAndBlankEncodedPassword() {
        assertThat(encoderWithMd5Fallback.matches(RAW_PASSWORD, null)).isFalse();
        assertThat(encoderWithMd5Fallback.matches(RAW_PASSWORD, "")).isFalse();
        assertThat(encoderWithMd5Fallback.matches(RAW_PASSWORD, "   ")).isFalse();
    }

    @Test
    void rejectsUnknownHashPrefix() {
        String fakeBcrypt = "$2a$10$abcdefghijklmnopqrstuvwxyz";

        assertThat(encoderWithMd5Fallback.matches(RAW_PASSWORD, fakeBcrypt)).isFalse();
    }

    @Test
    void encodeNullReturnsNull() {
        assertThat(encoderWithMd5Fallback.encode(null)).isNull();
    }
}
