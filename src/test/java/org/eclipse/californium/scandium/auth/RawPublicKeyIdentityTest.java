/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.auth;

import static org.junit.Assert.*;

import java.security.PublicKey;

import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.junit.Test;

public class RawPublicKeyIdentityTest {

	
	@Test
	public void testGetNameReturnsNamedInterfaceUri() throws Exception {
		String uriPrefix = "ni:///sha-256;";
		PublicKey key = DtlsTestTools.getPublicKey();
		RawPublicKeyIdentity id = new RawPublicKeyIdentity(key);
		assertTrue(id.getName().startsWith(uriPrefix));
		String hash = id.getName().substring(uriPrefix.length());
		assertFalse(hash.endsWith("="));
		assertFalse(hash.contains("+"));
		assertFalse(hash.contains("/"));
	}
	
	@Test
	public void testGetSubjectInfoReturnsEncodedKey() throws Exception {
		PublicKey key = DtlsTestTools.getPublicKey();
		RawPublicKeyIdentity id = new RawPublicKeyIdentity(key);
		assertArrayEquals(id.getKey().getEncoded(), id.getSubjectInfo());
	}
}
