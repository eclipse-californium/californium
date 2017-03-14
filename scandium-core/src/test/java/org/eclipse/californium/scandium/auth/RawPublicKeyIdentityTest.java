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

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class RawPublicKeyIdentityTest {

	private static final String URI_PREFIX = "ni:///sha-256;";

	@Test
	public void testGetNameReturnsNamedInterfaceUri() throws Exception {
		PublicKey key = DtlsTestTools.getPublicKey();
		RawPublicKeyIdentity id = new RawPublicKeyIdentity(key);
		assertThatNameIsValidNamedInterfaceUri(id.getName());
	}

	@Test
	public void testGetSubjectInfoReturnsEncodedKey() throws Exception {
		PublicKey key = DtlsTestTools.getPublicKey();
		RawPublicKeyIdentity id = new RawPublicKeyIdentity(key);
		assertArrayEquals(id.getKey().getEncoded(), id.getSubjectInfo());
	}

	@Test
	public void testConstructorCreatesPublicKeyFromSubjectInfo() throws IOException, GeneralSecurityException {
		// GIVEN a SubjectPublicKeyInfo object
		PublicKey key = DtlsTestTools.getPublicKey();
		byte[] subjectInfo = key.getEncoded();

		// WHEN creating a RawPublicKeyIdentity from it
		RawPublicKeyIdentity principal = new RawPublicKeyIdentity(subjectInfo);

		// THEN the principal contains the public key corresponding to the subject info
		assertThat(principal.getKey(), is(key));
	}

	private static void assertThatNameIsValidNamedInterfaceUri(String name) {
		assertTrue(name.startsWith(URI_PREFIX));
		String hash = name.substring(URI_PREFIX.length());
		assertFalse(hash.endsWith("="));
		assertFalse(hash.contains("+"));
		assertFalse(hash.contains("/"));
		assertFalse(hash.endsWith("\n"));
		assertFalse(hash.endsWith("\r"));
	}
}
