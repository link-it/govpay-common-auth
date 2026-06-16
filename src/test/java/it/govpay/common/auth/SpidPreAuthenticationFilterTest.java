package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class SpidPreAuthenticationFilterTest {

    @Test
    void constructorRejectsBlankHeader() {
        assertThatThrownBy(() -> new SpidPreAuthenticationFilter("", "TINIT-"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void returnsNullWhenHeaderMissing() {
        SpidPreAuthenticationFilter filter = new SpidPreAuthenticationFilter("X-SPID-SubjectCF", "TINIT-");
        assertThat(filter.getPreAuthenticatedPrincipal(new MockHttpServletRequest())).isNull();
    }

    @Test
    void stripsTinitPrefixWhenPresent() {
        SpidPreAuthenticationFilter filter = new SpidPreAuthenticationFilter("X-SPID-SubjectCF", "TINIT-");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-SPID-SubjectCF", "TINIT-RSSMRA80A01H501Z");

        assertThat(filter.getPreAuthenticatedPrincipal(request)).isEqualTo("RSSMRA80A01H501Z");
    }

    @Test
    void returnsRawValueWhenPrefixAbsent() {
        SpidPreAuthenticationFilter filter = new SpidPreAuthenticationFilter("X-SPID-SubjectCF", "TINIT-");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-SPID-SubjectCF", "RSSMRA80A01H501Z");

        assertThat(filter.getPreAuthenticatedPrincipal(request)).isEqualTo("RSSMRA80A01H501Z");
    }

    @Test
    void emptyPrefixDisablesStrip() {
        SpidPreAuthenticationFilter filter = new SpidPreAuthenticationFilter("X-SPID-SubjectCF", "");
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-SPID-SubjectCF", "TINIT-RSSMRA80A01H501Z");

        assertThat(filter.getPreAuthenticatedPrincipal(request)).isEqualTo("TINIT-RSSMRA80A01H501Z");
    }

    @Test
    void getPreAuthenticatedCredentialsAlwaysNA() {
        SpidPreAuthenticationFilter filter = new SpidPreAuthenticationFilter("X-SPID-SubjectCF", "TINIT-");
        assertThat(filter.getPreAuthenticatedCredentials(new MockHttpServletRequest())).isEqualTo("N/A");
    }
}
