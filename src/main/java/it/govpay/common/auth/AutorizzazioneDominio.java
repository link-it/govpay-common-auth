package it.govpay.common.auth;

/**
 * Decide se un'applicazione (identificata dalla sua utenza) e' autorizzata a operare su un
 * dominio, replicando la stessa semantica del legacy ({@code AuthorizationManager}):
 * autorizzazione "star" (tutti i domini) oppure autorizzazione esplicita su quel singolo
 * dominio.
 *
 * <p>Agnostico: non legge nessuna entita' propria. Le tabelle {@code utenze}/
 * {@code utenze_domini} non sono condivise in una libreria comune (sono infrastruttura di
 * sicurezza, non anagrafica di dominio) — ogni consumer (govpay-pendenze-api,
 * govpay-pafornode-api, govpay-console-api) mappa la propria vista e risolve i due booleani
 * con le proprie entita', poi chiama questo metodo per la decisione.
 */
public final class AutorizzazioneDominio {

	private AutorizzazioneDominio() {
	}

	public static boolean autorizzato(boolean autorizzazioneDominiStar, boolean autorizzatoSulDominioSpecifico) {
		return autorizzazioneDominiStar || autorizzatoSulDominioSpecifico;
	}
}
