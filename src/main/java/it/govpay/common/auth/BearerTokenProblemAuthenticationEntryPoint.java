package it.govpay.common.auth;

import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.util.StringUtils;

import tools.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Entry point per la chain OAuth2 (resource server JWT). Genera la response
 * combinando:
 * <ul>
 *   <li>header {@code WWW-Authenticate: Bearer ...} con eventuali parametri
 *       {@code realm}, {@code error}, {@code error_description},
 *       {@code error_uri}, {@code scope} (RFC 6750);</li>
 *   <li>body {@code application/problem+json}.</li>
 * </ul>
 *
 * <p>stessa logica di WWW-Authenticate header, body normalizzato a problem+json.
 */
public class BearerTokenProblemAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper;
    private final String realmName;

    public BearerTokenProblemAuthenticationEntryPoint(ObjectMapper objectMapper, String realmName) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
        this.realmName = realmName;
    }

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                         AuthenticationException authException) throws IOException {
        HttpStatus status = HttpStatus.UNAUTHORIZED;
        Map<String, String> parameters = new LinkedHashMap<>();
        if (StringUtils.hasText(realmName)) {
            parameters.put("realm", realmName);
        }
        String detail = "Autenticazione Bearer mancante o non valida.";
        if (authException instanceof OAuth2AuthenticationException oauthEx) {
            OAuth2Error error = oauthEx.getError();
            parameters.put("error", error.getErrorCode());
            if (StringUtils.hasText(error.getDescription())) {
                parameters.put("error_description", error.getDescription());
                detail = error.getDescription();
            }
            if (StringUtils.hasText(error.getUri())) {
                parameters.put("error_uri", error.getUri());
            }
            if (error instanceof BearerTokenError bearerTokenError) {
                if (StringUtils.hasText(bearerTokenError.getScope())) {
                    parameters.put("scope", bearerTokenError.getScope());
                }
                status = bearerTokenError.getHttpStatus();
            }
        }
        response.addHeader(HttpHeaders.WWW_AUTHENTICATE, computeWwwAuthenticate(parameters));
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        problem.setTitle(status.getReasonPhrase());
        problem.setInstance(URI.create(request.getRequestURI()));
        objectMapper.writeValue(response.getWriter(), problem);
    }

    private static String computeWwwAuthenticate(Map<String, String> parameters) {
        StringBuilder sb = new StringBuilder("Bearer");
        if (!parameters.isEmpty()) {
            sb.append(" ");
            int i = 0;
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                sb.append(entry.getKey()).append("=\"").append(entry.getValue()).append("\"");
                if (i != parameters.size() - 1) {
                    sb.append(", ");
                }
                i++;
            }
        }
        return sb.toString();
    }
}
