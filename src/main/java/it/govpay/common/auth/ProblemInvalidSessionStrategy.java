package it.govpay.common.auth;

import java.io.IOException;
import java.net.URI;
import java.util.Objects;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.web.session.InvalidSessionStrategy;

import tools.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Quando Spring Security rileva una sessione invalida (es. JSESSIONID inesistente o
 * appartenente a un'altra sessione), emette {@code 401 application/problem+json}
 * con detail "Sessione Scaduta", invece del redirect di default.
 *
 * <p>Allineato al pattern problem+json di common-auth con
 * {@link ProblemDetail} di Spring 7.
 */
public class ProblemInvalidSessionStrategy implements InvalidSessionStrategy {

    private final ObjectMapper objectMapper;

    public ProblemInvalidSessionStrategy(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @Override
    public void onInvalidSessionDetected(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Sessione Scaduta");
        problem.setTitle(HttpStatus.UNAUTHORIZED.getReasonPhrase());
        problem.setInstance(URI.create(request.getRequestURI()));
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), problem);
    }
}
