package it.govpay.common.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class LibraryInfoTest {

	@Test
	void getNameRestituisceIlNomeDellaLibreria() {
		assertEquals("govpay-common-auth", LibraryInfo.getName());
	}
}
