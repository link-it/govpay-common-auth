package it.govpay.common.auth;

import java.io.IOException;
import java.util.Objects;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import it.govpay.common.auth.spi.AuthEventListener;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Handler invocato dal {@link org.springframework.security.web.authentication.logout.LogoutFilter}
 * di Spring Security quando il logout va a buon fine.
 *
 * <p>Comportamento:
 * <ul>
 *   <li>cattura il principal dall'{@link Authentication} (Spring lo
 *       fornisce ancora qui, prima della clear del context);</li>
 *   <li>notifica {@link AuthEventListener#onLogout};</li>
 *   <li>imposta status {@code 204 No Content} (allineato a issue
 *       link-it/govpay-console-api#10 scope D).</li>
 * </ul>
 *
 * <p>L'invalidazione sessione e la cancellazione dei cookie (JSESSIONID,
 * XSRF-TOKEN) sono fatte dal {@link org.springframework.security.web.authentication.logout.LogoutFilter}
 * sulla base della configurazione della chain.
 */
public class GovpayLogoutSuccessHandler implements LogoutSuccessHandler {

    private final AuthEventListener eventListener;

    public GovpayLogoutSuccessHandler(AuthEventListener eventListener) {
        this.eventListener = Objects.requireNonNull(eventListener, "eventListener");
    }

    @Override
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {
        String principal = authentication != null ? authentication.getName() : null;
        eventListener.onLogout(principal, request);
        response.setStatus(HttpStatus.NO_CONTENT.value());
    }
}
