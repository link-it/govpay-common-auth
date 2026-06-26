package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class SslHeaderPreAuthenticationFilterTest {

    private final GovpayAuthProperties.SslHeader properties = newProperties();

    @Test
    void constructorRejectsBlankHeaderName() {
        GovpayAuthProperties.SslHeader p = new GovpayAuthProperties.SslHeader();
        p.setPrincipalHeaderName("");
        assertThatThrownBy(() -> new SslHeaderPreAuthenticationFilter(p))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void returnsNullWhenHeaderMissing() {
        SslHeaderPreAuthenticationFilter filter = new SslHeaderPreAuthenticationFilter(properties);
        MockHttpServletRequest request = new MockHttpServletRequest();
        assertThat(filter.getPreAuthenticatedPrincipal(request)).isNull();
        assertThat(filter.getPreAuthenticatedCredentials(request)).isEqualTo("N/A");
    }

    @Test
    void returnsNullWhenHeaderUnparsable() {
        SslHeaderPreAuthenticationFilter filter = new SslHeaderPreAuthenticationFilter(properties);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(properties.getPrincipalHeaderName(), "not-a-cert");
        assertThat(filter.getPreAuthenticatedPrincipal(request)).isNull();
    }

    @Test
    void translateReplaceLiteralMapsV1Escapes() {
        assertThat(SslHeaderPreAuthenticationFilter.translateReplaceLiteral("\\t", "default")).isEqualTo("\t");
        assertThat(SslHeaderPreAuthenticationFilter.translateReplaceLiteral("\\r", "default")).isEqualTo("\r");
        assertThat(SslHeaderPreAuthenticationFilter.translateReplaceLiteral("\\n", "default")).isEqualTo("\n");
        assertThat(SslHeaderPreAuthenticationFilter.translateReplaceLiteral("\\r\\n", "default")).isEqualTo("\r\n");
        assertThat(SslHeaderPreAuthenticationFilter.translateReplaceLiteral("\\s", "default")).isEqualTo(" ");
    }

    @Test
    void translateReplaceLiteralFallsBackOnNullOrEmpty() {
        assertThat(SslHeaderPreAuthenticationFilter.translateReplaceLiteral(null, "DEF")).isEqualTo("DEF");
        assertThat(SslHeaderPreAuthenticationFilter.translateReplaceLiteral("", "DEF")).isEqualTo("DEF");
    }

    @Test
    void translateReplaceLiteralPassesUnknownStringAsIs() {
        // YAML-nativo: utenti che mettono direttamente il carattere reale
        // ("\t" interpretato dal YAML = tab vero) lo vedono passare invariato.
        assertThat(SslHeaderPreAuthenticationFilter.translateReplaceLiteral("\t", "DEF")).isEqualTo("\t");
        assertThat(SslHeaderPreAuthenticationFilter.translateReplaceLiteral("xyz", "DEF")).isEqualTo("xyz");
    }

    @Test
    void applyReplaceStripsAndRestoresMarkers() {
        String pem = SslHeaderPreAuthenticationFilter.PEM_BEGIN + "BODY\twith\ttabs" + SslHeaderPreAuthenticationFilter.PEM_END;
        StringBuilder out = new StringBuilder();
        boolean forceEnrich = SslHeaderPreAuthenticationFilter.applyReplace(pem, "\t", "\n", out);
        assertThat(forceEnrich).isTrue();
        // body modificato, BEGIN/END strippati nel risultato (saranno ri-aggiunti da addPEMDeclaration)
        assertThat(out.toString()).isEqualTo("BODY\nwith\ntabs");
    }

    @Test
    void applyReplaceWithoutMarkers() {
        String body = "raw-body\twith\ttabs";
        StringBuilder out = new StringBuilder();
        boolean forceEnrich = SslHeaderPreAuthenticationFilter.applyReplace(body, "\t", "\n", out);
        assertThat(forceEnrich).isFalse();
        assertThat(out.toString()).isEqualTo("raw-body\nwith\ntabs");
    }

    @Test
    void applyReplaceNoOpWhenSourceAbsent() {
        StringBuilder out = new StringBuilder();
        boolean forceEnrich = SslHeaderPreAuthenticationFilter.applyReplace("body-no-tabs", "\t", "\n", out);
        assertThat(forceEnrich).isFalse();
        assertThat(out.toString()).isEqualTo("body-no-tabs");
    }

    @Test
    void addPEMDeclarationAdjacentWhenForceEnrichTrue() {
        String body = "BODY\nwith\nnewlines";
        String result = SslHeaderPreAuthenticationFilter.addPEMDeclaration(body, true);
        // forceEnrich=true → markers adiacenti, no newline aggiuntivo
        assertThat(result).isEqualTo(
                SslHeaderPreAuthenticationFilter.PEM_BEGIN + body + SslHeaderPreAuthenticationFilter.PEM_END);
    }

    @Test
    void addPEMDeclarationWithNewlineWhenForceEnrichFalse() {
        String body = "BODY";
        String result = SslHeaderPreAuthenticationFilter.addPEMDeclaration(body, false);
        // forceEnrich=false → markers con newline di separazione
        assertThat(result).isEqualTo(
                SslHeaderPreAuthenticationFilter.PEM_BEGIN + "\n" + body + "\n" + SslHeaderPreAuthenticationFilter.PEM_END);
    }

    @Test
    void addPEMDeclarationLeavesMarkersIfAlreadyPresent() {
        String already = SslHeaderPreAuthenticationFilter.PEM_BEGIN + "BODY" + SslHeaderPreAuthenticationFilter.PEM_END;
        assertThat(SslHeaderPreAuthenticationFilter.addPEMDeclaration(already, true)).isEqualTo(already);
        assertThat(SslHeaderPreAuthenticationFilter.addPEMDeclaration(already, false)).isEqualTo(already);
    }

    private static GovpayAuthProperties.SslHeader newProperties() {
        GovpayAuthProperties.SslHeader p = new GovpayAuthProperties.SslHeader();
        p.setPrincipalHeaderName("X-SSL-Client-Cert");
        return p;
    }
}
