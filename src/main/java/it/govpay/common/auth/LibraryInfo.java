package it.govpay.common.auth;

/**
 * Informazioni di base sulla libreria di autorizzazione GovPay.
 *
 * <p>Classe minimale di servizio: serve principalmente come segnaposto
 * iniziale e per consentire la generazione del report di code coverage.</p>
 */
public final class LibraryInfo {

	/** Nome simbolico della libreria. */
	public static final String NAME = "govpay-common-auth";

	private LibraryInfo() {
		// classe di sole costanti/utility: non istanziabile
	}

	/**
	 * Restituisce il nome della libreria.
	 *
	 * @return il nome della libreria
	 */
	public static String getName() {
		return NAME;
	}
}
