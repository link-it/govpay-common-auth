package it.govpay.common.auth;

import java.io.ByteArrayInputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Objects;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import it.govpay.common.auth.spi.AuthType;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter pre-auth per il caso in cui un reverse proxy / API gateway termina
 * la mTLS e propaga il certificato client (o solo il subject DN) via header
 * HTTP.
 *
 * <p>Porting V1 fedele di {@code it.govpay.rs.v1.authentication.preauth.filter.SSLHeaderPreAuthFilter},
 * con la pipeline che V1 ereditava da {@code CertificateUtils} di openspcoop2-utils,
 * reimplementata qui con JDK standard + commons-codec per evitare la
 * dipendenza esterna.
 *
 * <p>Pipeline (in ordine):
 * <ol>
 *   <li><b>Replace caratteri</b> (se abilitato): protegge i marker
 *       {@code -----BEGIN CERTIFICATE-----}/{@code -----END CERTIFICATE-----},
 *       sostituisce {@code replaceSource} con {@code replaceDest} nel body PEM
 *       (max 10000 iterazioni come safety net V1), re-inserisce i marker.
 *       Caso d'uso: nginx con {@code $ssl_client_escaped_cert} che traduce
 *       {@code \n} → {@code \t} per fit-in-header. Default V1:
 *       sorgente {@code \t}, destinazione {@code \n}.</li>
 *   <li><b>PEM enrichment</b>: re-aggiunge i marker se erano stati strippati
 *       per il replace (V1: stesso comportamento, con o senza newline tra
 *       marker e body a seconda che fossero gia' presenti nell'input originale).</li>
 *   <li><b>Try-fallback decoding</b> (replica del quirk V1): se uno qualsiasi
 *       tra {@code urlDecode}, {@code base64Decode}, {@code hexDecode} e' true,
 *       tenta in sequenza URL → Base64 → (Hex, se hexDecode era true) finche'
 *       uno produce un cert parsabile. Se tutti falliscono, ritorna {@code null}.</li>
 *   <li><b>Parsing X.509</b>: via JDK {@code CertificateFactory.getInstance("X.509")},
 *       che accetta sia DER sia PEM in input (vs V1 {@code ArchiveLoader.load}
 *       che secondo il commento V1 supportava solo DER: V2 e' piu' permissiva
 *       — inputs che V1 rifiutava possono essere accettati, ma tutti i casi
 *       V1-validi continuano a funzionare).</li>
 *   <li><b>Subject DN</b>: {@code X509Certificate.getSubjectX500Principal().getName()},
 *       formato RFC 2253, byte-per-byte identico a V1 {@code CertificatePrincipal.toString()}
 *       (che internamente delega a {@code X500Principal.toString()}).</li>
 * </ol>
 *
 * <p>Divergenza V2 esplicita rispetto a V1: in caso di failure del decoding+parsing,
 * V1 ritornava il valore raw dell'header come principal (auth poi falliva con
 * "utenza non trovata" mascherando l'errore reale). V2 ritorna {@code null}
 * → {@link AbstractPreAuthenticatedProcessingFilter} salta la request,
 * eventuale 401 viene emesso dall'entry point della chain con diagnostica
 * piu' chiara.
 */
public class SslHeaderPreAuthenticationFilter extends AbstractPreAuthenticatedProcessingFilter {

    private static final Logger log = LoggerFactory.getLogger(SslHeaderPreAuthenticationFilter.class);

    static final String PEM_BEGIN = "-----BEGIN CERTIFICATE-----";
    static final String PEM_END = "-----END CERTIFICATE-----";
    private static final int MAX_REPLACE_ITERATIONS = 10_000;
    private static final String DEFAULT_REPLACE_SOURCE = "\t";
    private static final String DEFAULT_REPLACE_DEST = "\n";

    private final GovpayAuthProperties.SslHeader properties;

    public SslHeaderPreAuthenticationFilter(GovpayAuthProperties.SslHeader properties) {
        this.properties = Objects.requireNonNull(properties, "properties");
        if (properties.getPrincipalHeaderName() == null || properties.getPrincipalHeaderName().isBlank()) {
            throw new IllegalArgumentException("principalHeaderName must not be blank");
        }
    }

    @Override
    protected Object getPreAuthenticatedPrincipal(HttpServletRequest request) {
        String headerValue = request.getHeader(properties.getPrincipalHeaderName());
        if (headerValue == null || headerValue.isBlank()) {
            return null;
        }
        log.debug("SSL_HEADER: letto principal grezzo da header [{}], lunghezza={}",
                properties.getPrincipalHeaderName(), headerValue.length());

        // Step 1: replace caratteri (al di fuori della pipeline di decoding,
        // come fa V1 in SSLHeaderPreAuthFilter.decodePrincipal).
        boolean forceEnrichPEMBeginEnd = false;
        if (properties.isReplaceCharactersEnabled()) {
            String source = translateReplaceLiteral(properties.getReplaceSource(), DEFAULT_REPLACE_SOURCE);
            String dest = translateReplaceLiteral(properties.getReplaceDest(), DEFAULT_REPLACE_DEST);
            StringBuilder sb = new StringBuilder();
            forceEnrichPEMBeginEnd = applyReplace(headerValue, source, dest, sb);
            headerValue = sb.toString();
        }

        // Step 2: re-aggiunge PEM BEGIN/END se erano stati strippati per il replace.
        // NB: V1 controlla anche config.isEnrichPEMBeginEnd() ma in SSLHeaderPreAuthFilter
        // quel flag non viene mai settato → default false → solo forceEnrichPEMBeginEnd conta.
        if (forceEnrichPEMBeginEnd) {
            headerValue = addPEMDeclaration(headerValue, true);
        }

        // Step 3: try-fallback decoding + parsing X.509.
        X509Certificate cert = tryDecodeAndParse(headerValue);
        if (cert == null) {
            log.debug("SSL_HEADER: parsing del certificato fallito su tutti i decoder tentati");
            return null;
        }

        String subjectDn = cert.getSubjectX500Principal().getName();
        log.debug("SSL_HEADER: subject DN estratto: [{}]", subjectDn);
        return subjectDn;
    }

    @Override
    protected Object getPreAuthenticatedCredentials(HttpServletRequest request) {
        return "N/A";
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            Authentication authResult) throws java.io.IOException, ServletException {
        super.successfulAuthentication(request, response, authResult);
        request.setAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE, AuthType.SSL_HEADER);
        request.setAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE_PRINCIPAL, authResult.getName());
    }

    /**
     * Replica V1: traduce le stringhe letterali V1 (es. {@code "\\t"} dalla
     * properties file) nei caratteri reali. Stringhe non riconosciute passano
     * as-is (consente di scrivere direttamente il carattere reale in YAML).
     */
    static String translateReplaceLiteral(String input, String fallbackDefault) {
        if (input == null || input.isEmpty()) {
            return fallbackDefault;
        }
        return switch (input) {
            case "\\t" -> "\t";
            case "\\r" -> "\r";
            case "\\n" -> "\n";
            case "\\r\\n" -> "\r\n";
            case "\\s" -> " ";
            default -> input;
        };
    }

    /**
     * Replica V1 {@code SSLHeaderPreAuthFilter.replaceCharacters}: protegge i
     * marker BEGIN/END, applica il replace nel body, ritorna {@code true}
     * se i marker erano presenti nell'input (per guidare la re-aggiunta in
     * {@link #addPEMDeclaration}).
     */
    static boolean applyReplace(String input, String source, String dest, StringBuilder out) {
        String body = input;
        boolean forceEnrich = false;
        if (body.startsWith(PEM_BEGIN) && body.length() > PEM_BEGIN.length()) {
            body = body.substring(PEM_BEGIN.length());
            forceEnrich = true;
        }
        if (body.endsWith(PEM_END) && body.length() > PEM_END.length()) {
            body = body.substring(0, body.length() - PEM_END.length());
        }
        int iter = 0;
        while (body.contains(source) && iter < MAX_REPLACE_ITERATIONS) {
            body = body.replace(source, dest);
            iter++;
        }
        out.append(body);
        return forceEnrich;
    }

    /**
     * Replica V1 {@code SSLHeaderPreAuthFilter.addPEMDeclaration}: re-aggiunge
     * i marker. Quirk V1: il separatore tra marker e body e' {@code ""} se i
     * marker erano stati strippati (perche' il body, post-replace, ha gia' le
     * sue newline), oppure {@code "\n"} se i marker non c'erano e li stiamo
     * forzando ex novo.
     */
    static String addPEMDeclaration(String certificate, boolean forceEnrichPEMBeginEnd) {
        String result = certificate;
        if (!result.startsWith(PEM_BEGIN)) {
            result = PEM_BEGIN + (forceEnrichPEMBeginEnd ? "" : "\n") + result;
        }
        if (!result.endsWith(PEM_END)) {
            result = result + (forceEnrichPEMBeginEnd ? "" : "\n") + PEM_END;
        }
        return result;
    }

    /**
     * Try-fallback V1: se almeno uno tra {@code urlDecode}/{@code base64Decode}/
     * {@code hexDecode} e' attivo, tenta in sequenza URL → Base64 (e Hex se
     * l'utente l'aveva richiesto) finche' uno produce un cert parsabile.
     *
     * <p>NB: replica il quirk V1 per cui anche se l'utente ha chiesto solo
     * {@code base64Decode}, V1 tenta comunque PRIMA URL decode (la config
     * {@code config.setUrlDecode(true)} viene forzata indipendentemente
     * dall'intent originale dell'utente). Questo significa che, ad esempio,
     * un input PEM URL-encoded viene comunque accettato da una config che
     * tecnicamente chiedeva solo Base64. Comportamento V1 by-design o bug
     * dipende dall'interpretazione; lo replichiamo per fedelta'.
     */
    private X509Certificate tryDecodeAndParse(String input) {
        boolean anyDecodeFlag = properties.isUrlDecode()
                || properties.isBase64Decode()
                || properties.isHexDecode();
        if (!anyDecodeFlag) {
            return parseCertificateSilent(input.getBytes(StandardCharsets.UTF_8));
        }
        // Attempt URL decode
        try {
            String urlDecoded = URLDecoder.decode(input, StandardCharsets.UTF_8);
            X509Certificate cert = parseCertificateSilent(urlDecoded.getBytes(StandardCharsets.UTF_8));
            if (cert != null) return cert;
        } catch (Exception ex) {
            log.debug("SSL_HEADER: URL decode fallito", ex);
        }
        // Attempt Base64 decode
        try {
            byte[] base64Bytes = Base64.getDecoder().decode(input);
            X509Certificate cert = parseCertificateSilent(base64Bytes);
            if (cert != null) return cert;
        } catch (Exception ex) {
            log.debug("SSL_HEADER: Base64 decode fallito", ex);
        }
        // Attempt Hex decode (solo se richiesto dall'utente, conformemente al
        // branch V1 gated da isUrlDecodeOrBase64DecodeOrHexDecode).
        if (properties.isHexDecode()) {
            try {
                byte[] hexBytes = Hex.decodeHex(input);
                X509Certificate cert = parseCertificateSilent(hexBytes);
                if (cert != null) return cert;
            } catch (Exception ex) {
                log.debug("SSL_HEADER: Hex decode fallito", ex);
            }
        }
        return null;
    }

    private static X509Certificate parseCertificateSilent(byte[] bytes) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
        } catch (Exception ex) {
            return null;
        }
    }
}
