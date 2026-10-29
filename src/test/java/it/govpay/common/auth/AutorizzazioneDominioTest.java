package it.govpay.common.auth;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class AutorizzazioneDominioTest {

	@Test
	void autorizzatoSeStar() {
		assertThat(AutorizzazioneDominio.autorizzato(true, false)).isTrue();
	}

	@Test
	void autorizzatoSeSpecifico() {
		assertThat(AutorizzazioneDominio.autorizzato(false, true)).isTrue();
	}

	@Test
	void autorizzatoSeEntrambi() {
		assertThat(AutorizzazioneDominio.autorizzato(true, true)).isTrue();
	}

	@Test
	void nonAutorizzatoSeNessuno() {
		assertThat(AutorizzazioneDominio.autorizzato(false, false)).isFalse();
	}
}
