package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class HeaderPreAuthenticationFilterTest {

    @Test
    void constructorRejectsNullList() {
        assertThatThrownBy(() -> new HeaderPreAuthenticationFilter(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void constructorRejectsEmptyList() {
        assertThatThrownBy(() -> new HeaderPreAuthenticationFilter(List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void returnsFirstNonNullHeader() {
        HeaderPreAuthenticationFilter filter = new HeaderPreAuthenticationFilter(
                List.of("X-Pre-Auth-User", "X-Authenticated-User"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Authenticated-User", "alice");

        assertThat(filter.getPreAuthenticatedPrincipal(request)).isEqualTo("alice");
    }

    @Test
    void firstHeaderTakesPriorityOverLater() {
        HeaderPreAuthenticationFilter filter = new HeaderPreAuthenticationFilter(
                List.of("X-Pre-Auth-User", "X-Authenticated-User"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Pre-Auth-User", "alice");
        request.addHeader("X-Authenticated-User", "bob");

        assertThat(filter.getPreAuthenticatedPrincipal(request)).isEqualTo("alice");
    }

    @Test
    void returnsNullWhenAllHeadersMissing() {
        HeaderPreAuthenticationFilter filter = new HeaderPreAuthenticationFilter(
                List.of("X-Pre-Auth-User", "X-Authenticated-User"));
        assertThat(filter.getPreAuthenticatedPrincipal(new MockHttpServletRequest())).isNull();
    }

    @Test
    void skipsBlankHeaderValues() {
        HeaderPreAuthenticationFilter filter = new HeaderPreAuthenticationFilter(
                List.of("X-Pre-Auth-User", "X-Authenticated-User"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Pre-Auth-User", "   ");
        request.addHeader("X-Authenticated-User", "alice");

        assertThat(filter.getPreAuthenticatedPrincipal(request)).isEqualTo("alice");
    }
}
