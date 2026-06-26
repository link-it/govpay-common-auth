package it.govpay.common.auth;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import tools.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Handler invocato sul logout della chain OAuth2/OIDC. Costruisce l'URL di
 * logout sul server di autorizzazione (con {@code post_logout_redirect_uri}
 * e {@code id_token_hint} se presente in query) e lo ritorna nel body JSON
 * {@code {"logoutUrl":"..."}}.
 *
 * <p>Se {@code logoutUri} o {@code postLogoutRedirectUri} non sono configurati,
 * il handler emette {@code 204 No Content} senza body.
 */
public class Oauth2LogoutSuccessHandler implements LogoutSuccessHandler {

    /** Parametro dal quale leggere {@code id_token_hint}. */
    public static final String PARAM_ID_TOKEN_HINT = "id_token_hint";

    private static final Logger log = LoggerFactory.getLogger(Oauth2LogoutSuccessHandler.class);

    private final String logoutUri;
    private final String postLogoutRedirectUri;
    private final ObjectMapper objectMapper;

    public Oauth2LogoutSuccessHandler(String logoutUri,
                                      String postLogoutRedirectUri,
                                      ObjectMapper objectMapper) {
        this.logoutUri = logoutUri;
        this.postLogoutRedirectUri = postLogoutRedirectUri;
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                                Authentication authentication) throws IOException {
        if (logoutUri == null || logoutUri.isBlank()
                || postLogoutRedirectUri == null || postLogoutRedirectUri.isBlank()) {
            response.setStatus(HttpStatus.NO_CONTENT.value());
            return;
        }
        StringBuilder sb = new StringBuilder(logoutUri);
        sb.append("?post_logout_redirect_uri=")
                .append(URLEncoder.encode(postLogoutRedirectUri, StandardCharsets.UTF_8));
        String idToken = request.getParameter(PARAM_ID_TOKEN_HINT);
        if (idToken != null && !idToken.isBlank()) {
            sb.append("&id_token_hint=").append(URLEncoder.encode(idToken, StandardCharsets.UTF_8));
        }
        String fullUrl = sb.toString();
        log.debug("OAUTH2 logout URL costruito: {}", fullUrl);

        Map<String, String> body = new LinkedHashMap<>();
        body.put("logoutUrl", fullUrl);
        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), body);
    }
}
