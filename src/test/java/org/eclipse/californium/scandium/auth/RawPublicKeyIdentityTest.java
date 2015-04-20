package org.eclipse.californium.scandium.auth;

import static org.junit.Assert.*;

import java.security.PublicKey;

import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.junit.Test;

public class RawPublicKeyIdentityTest {

	
	@Test
	public void testGetNameReturnsNamedInterfaceUri() throws Exception {
		PublicKey key = DtlsTestTools.getPublicKey();
		RawPublicKeyIdentity id = new RawPublicKeyIdentity(key);
		assertTrue(id.getName().startsWith("ni:///sha-256;"));
		assertFalse(id.getName().endsWith("="));
	}

}
