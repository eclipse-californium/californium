/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.auth;

import static org.eclipse.californium.elements.util.TestCertificatesTools.*;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assume.assumeNoException;
import static org.junit.Assume.assumeNotNull;

import java.io.IOException;
import java.security.GeneralSecurityException;

import org.eclipse.californium.elements.util.JceNames;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.TestCertificatesTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Verifies behavior of {@link X509CertPath}.
 *
 */
public class X509CertPathIdentityTest {

	public static final String ALIAS_CLIENT = "client";

	private static SslContextUtil.Credentials ecCredentials;
	private static SslContextUtil.Credentials ed25519Credentials;

	/**
	 * Load chains.
	 */
	@BeforeClass
	public static void init() throws IOException {
		try {
			ecCredentials = SslContextUtil.loadCredentials(KEY_STORE_URI, ALIAS_CLIENT, KEY_STORE_PASSWORD,
					KEY_STORE_PASSWORD);
		} catch (GeneralSecurityException e) {
			assumeNoException("vm's without EC are not usable for CoAP!", e);
		}
		if (JceProviderUtil.isSupported(JceNames.ED25519) && SslContextUtil.isAvailableFromUri(EDDSA_KEY_STORE_URI)) {
			try {
				ed25519Credentials = SslContextUtil.loadCredentials(EDDSA_KEY_STORE_URI, "clienteddsa",
						KEY_STORE_PASSWORD, KEY_STORE_PASSWORD);
			} catch (IllegalArgumentException e) {
				// ignores missing Ed25519
			} catch (GeneralSecurityException e) {
				// ignores missing Ed25519
			}
		}
	}

	@Test
	public void testGetNameReturnsNamedInterfaceUri() {
		X509CertPath id = X509CertPath.fromCertificatesChain(ecCredentials.getCertificateChain());
		assertThat(id.getName(), is(ecCredentials.getCertificateChain()[0].getSubjectX500Principal().getName()));
	}

	@Test
	public void testGetCNReturnsCN() {
		X509CertPath id = X509CertPath.fromCertificatesChain(ecCredentials.getCertificateChain());
		assertThat(id.getCN(), is("cf-client"));
	}

	@Test
	public void testGetTargetReturnsFirstCertificate() {
		X509CertPath id = X509CertPath.fromCertificatesChain(ecCredentials.getCertificateChain());
		assertThat(id.getTarget(), is(ecCredentials.getCertificateChain()[0]));
	}

	@Test
	public void testConstructorCreatesEcChainFromBytes() throws GeneralSecurityException {

		X509CertPath id = X509CertPath.fromCertificatesChain(ecCredentials.getCertificateChain());

		// GIVEN a SubjectPublicKeyInfo object
		byte[] chain = id.toByteArray();

		// WHEN creating a RawPublicKeyIdentity from it
		X509CertPath principal = X509CertPath.fromBytes(chain);

		// THEN the principal is the same
		assertThat(id, is(principal));
		assertThat(id.getPath(), is(principal.getPath()));
		TestCertificatesTools.assertSigning("X509", ecCredentials.getPrivateKey(), principal.getTarget().getPublicKey(), "SHA256withECDSA");
	}

	@Test
	public void testConstructorCreatesEd25519ChainFromBytes() throws GeneralSecurityException {
		assumeNotNull("Ed25519 not supported by vm!", ed25519Credentials);

		X509CertPath id = X509CertPath.fromCertificatesChain(ed25519Credentials.getCertificateChain());

		// GIVEN a SubjectPublicKeyInfo object
		byte[] chain = id.toByteArray();

		// WHEN creating a RawPublicKeyIdentity from it
		X509CertPath principal = X509CertPath.fromBytes(chain);

		// THEN the principal is the same
		assertThat(id, is(principal));
		assertThat(id.getPath(), is(principal.getPath()));
		TestCertificatesTools.assertSigning("X509", ed25519Credentials.getPrivateKey(), principal.getTarget().getPublicKey(), "ED25519");
	}
}
