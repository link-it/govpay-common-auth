package it.govpay.common.auth;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;

import tools.jackson.databind.ObjectMapper;

import it.govpay.common.auth.spi.AuthType;
import it.govpay.common.auth.spi.JsonLoginResponseWriter;

import jakarta.servlet.http.HttpServletResponse;

/**
 * Default minimale di {@link JsonLoginResponseWriter}: scrive un JSON
 * {@code {"principal":"...","autenticazione":"FORM"}}. Sostituibile dal
 * consumer registrando un proprio bean (es. console-api scrive il
 * {@code Profilo}).
 */
public class DefaultJsonLoginResponseWriter implements JsonLoginResponseWriter {

    private final ObjectMapper objectMapper;

    public DefaultJsonLoginResponseWriter(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @Override
    public void writeSuccessBody(HttpServletResponse response, Authentication authentication) throws IOException {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("principal", authentication.getName());
        body.put("autenticazione", AuthType.FORM.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), body);
    }
}
