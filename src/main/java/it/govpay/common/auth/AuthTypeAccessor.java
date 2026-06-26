package it.govpay.common.auth;

import it.govpay.common.auth.spi.AuthType;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Accessor che recupera l'{@link AuthType} stampato sulla request da
 * {@link AuthTypeStampingFilter}.
 *
 * <p>Usato dai controller del consumer (es. {@code ProfiloController} di
 * console-api) per valorizzare il campo {@code Profilo.autenticazione}.
 */
public final class AuthTypeAccessor {

    private AuthTypeAccessor() {
        // utility
    }

    /**
     * @param request request HTTP corrente, mai {@code null}
     * @return l'{@link AuthType} riconosciuto dal filter, oppure {@code null}
     *         se la request non e' stata processata da {@link AuthTypeStampingFilter}
     *         o se il metodo di autenticazione non e' noto.
     */
    public static AuthType current(HttpServletRequest request) {
        Object value = request.getAttribute(AuthTypeStampingFilter.REQUEST_ATTRIBUTE);
        return value instanceof AuthType type ? type : null;
    }
}
