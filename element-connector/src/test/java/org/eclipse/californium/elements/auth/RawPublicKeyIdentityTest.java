/*******************************************************************************
 * Copyright (c) 2015, 2018 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.auth;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeNoException;
import static org.junit.Assume.assumeNotNull;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.eclipse.californium.elements.util.JceNames;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.elements.util.TestCertificatesTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Verifies behavior of {@link RawPublicKeyIdentity}.
 *
 */
public class RawPublicKeyIdentityTest {

	private static final String URI_PREFIX = "ni:///sha-256;";
	private static KeyPair ecKeyPair;
	private static KeyPair ed25519KeyPair;
	private static KeyPair ed448KeyPair;

	/**
	 * Creates a public key.
	 */
	@BeforeClass
	public static void init() throws IOException {
		JceProviderUtil.init();
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
			ecKeyPair = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			assumeNoException("vm's without EC are not usable for CoAP!", e);
		}
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(JceNames.OID_ED25519);
			ed25519KeyPair = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// ignores missing Ed25519
		}
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance(JceNames.OID_ED448);
			ed448KeyPair = generator.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// ignores missing Ed448
		}
	}

	@Test
	public void testGetNameReturnsNamedInterfaceUri() {
		RawPublicKeyIdentity id = new RawPublicKeyIdentity(ecKeyPair.getPublic());
		assertThatNameIsValidNamedInterfaceUri(id.getName());
	}

	@Test
	public void testGetSubjectInfoReturnsEncodedKey() {
		RawPublicKeyIdentity id = new RawPublicKeyIdentity(ecKeyPair.getPublic());
		assertArrayEquals(id.getKey().getEncoded(), id.getSubjectInfo());
	}

	@Test
	public void testConstructorCreatesEcPublicKeyFromSubjectInfo() throws GeneralSecurityException {

		// GIVEN a SubjectPublicKeyInfo object
		byte[] subjectInfo = ecKeyPair.getPublic().getEncoded();

		// WHEN creating a RawPublicKeyIdentity from it
		RawPublicKeyIdentity principal = new RawPublicKeyIdentity(subjectInfo, ecKeyPair.getPublic().getAlgorithm());

		// THEN the principal contains the public key corresponding to the
		// subject info
		assertThat(principal.getKey(), is(ecKeyPair.getPublic()));

		// WHEN creating a RawPublicKeyIdentity from it
		principal = new RawPublicKeyIdentity(subjectInfo);

		// THEN the principal contains the public key corresponding to the
		// subject info
		assertThat(principal.getKey(), is(ecKeyPair.getPublic()));

		TestCertificatesTools.assertSigning("RPK", ecKeyPair.getPrivate(), principal.getKey(), "SHA256withECDSA");
	}

	@Test
	public void testConstructorCreatesEd25519PublicKeyFromSubjectInfo() throws GeneralSecurityException {
		assumeNotNull("Ed25519 not supported by vm!", ed25519KeyPair);
		// GIVEN a SubjectPublicKeyInfo object
		byte[] subjectInfo = ed25519KeyPair.getPublic().getEncoded();

		// WHEN creating a RawPublicKeyIdentity from it
		RawPublicKeyIdentity principal = new RawPublicKeyIdentity(subjectInfo, ed25519KeyPair.getPublic().getAlgorithm());

		// THEN the principal contains the public key corresponding to the
		// subject info
		assertThat(principal.getKey(), is(ed25519KeyPair.getPublic()));

		// WHEN creating a RawPublicKeyIdentity from it
		principal = new RawPublicKeyIdentity(subjectInfo);

		// THEN the principal contains the public key corresponding to the
		// subject info
		assertThat(principal.getKey(), is(ed25519KeyPair.getPublic()));
		TestCertificatesTools.assertSigning("RPK", ed25519KeyPair.getPrivate(), principal.getKey(), "ED25519");
	}

	@Test
	public void testConstructorCreatesEd448PublicKeyFromSubjectInfo() throws GeneralSecurityException {
		assumeNotNull("Ed448 is not supported by vm!", ed448KeyPair);
		// GIVEN a SubjectPublicKeyInfo object
		byte[] subjectInfo = ed448KeyPair.getPublic().getEncoded();

		// WHEN creating a RawPublicKeyIdentity from it
		RawPublicKeyIdentity principal = new RawPublicKeyIdentity(subjectInfo, ed448KeyPair.getPublic().getAlgorithm());

		// THEN the principal contains the public key corresponding to the
		// subject info
		assertThat(principal.getKey(), is(ed448KeyPair.getPublic()));

		// WHEN creating a RawPublicKeyIdentity from it
		principal = new RawPublicKeyIdentity(subjectInfo);

		// THEN the principal contains the public key corresponding to the
		// subject info
		assertThat(principal.getKey(), is(ed448KeyPair.getPublic()));
		TestCertificatesTools.assertSigning("RPK", ed448KeyPair.getPrivate(), principal.getKey(), "ED448");
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
