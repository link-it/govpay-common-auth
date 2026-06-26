package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.web.session.SessionInformationExpiredEvent;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

class ProblemSessionStrategiesTest {

    private final ObjectMapper objectMapper = JsonMapper.builder().build();

    @Test
    void invalidSessionStrategyEmits401ProblemJson() throws Exception {
        ProblemInvalidSessionStrategy strategy = new ProblemInvalidSessionStrategy(objectMapper);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/profilo");
        MockHttpServletResponse response = new MockHttpServletResponse();

        strategy.onInvalidSessionDetected(request, response);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).isEqualTo("application/problem+json");
        String body = response.getContentAsString();
        assertThat(body).contains("\"status\":401");
        assertThat(body).contains("Sessione Scaduta");
        assertThat(body).contains("\"instance\":\"/profilo\"");
    }

    @Test
    void expiredSessionStrategyEmits401ProblemJson() throws Exception {
        ProblemSessionInformationExpiredStrategy strategy = new ProblemSessionInformationExpiredStrategy(objectMapper);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/pendenze");
        MockHttpServletResponse response = new MockHttpServletResponse();
        SessionInformation info = new SessionInformation("alice", "session-id", new java.util.Date());
        SessionInformationExpiredEvent event = new SessionInformationExpiredEvent(info, request, response);

        strategy.onExpiredSessionDetected(event);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getContentType()).isEqualTo("application/problem+json");
        String body = response.getContentAsString();
        assertThat(body).contains("Sessione Scaduta");
        assertThat(body).contains("\"instance\":\"/pendenze\"");
    }
}
