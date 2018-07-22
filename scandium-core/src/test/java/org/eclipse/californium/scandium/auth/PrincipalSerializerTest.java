/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.auth;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;

import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.util.DatagramReader;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Verifies behavior of {@link PrincipalSerializer}.
 *
 */
@Category(Small.class)
public class PrincipalSerializerTest {

	private static PublicKey publicKey;
	private static Certificate[] certificateChain;

	/**
	 * Creates a public key to be used in test cases.
	 * 
	 * @throws GeneralSecurityException if the demo server certificate chain
	 *              cannot be read.
	 * @throws IOException if the demo server certificate chain
	 *              cannot be read.
	 */
	@BeforeClass
	public static void init() throws IOException, GeneralSecurityException {
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			KeyPair keyPair = generator.generateKeyPair();
			publicKey = keyPair.getPublic();
		} catch (NoSuchAlgorithmException e) {
			// every VM is required to support RSA
		}
		certificateChain = DtlsTestTools.getServerCertificateChain();
	}

	/**
	 * Verifies that a pre-shared key identity that has been serialized using the
	 * serialize method can be re-instantiated properly using the deserialize
	 * method.
	 */
	@Test
	public void testSerializedPSKIdentityCanBeDeserialized() {

		testSerializedPSKIdentityCanBeDeserialized(new PreSharedKeyIdentity("iot.eclipse.org", "acme"));
	}

	/**
	 * Verifies that a pre-shared key identity without a virtual host that has been
	 * serialized using the serialize method can be re-instantiated properly using
	 * the deserialize method.
	 */
	@Test
	public void testSerializedPSKIdentityWithoutHostCanBeDeserialized() {

		testSerializedPSKIdentityCanBeDeserialized(new PreSharedKeyIdentity("acme"));
	}

	private static void testSerializedPSKIdentityCanBeDeserialized(PreSharedKeyIdentity pskIdentity) {

		try {
			// WHEN serializing the identity to a byte array
			DatagramWriter writer = new DatagramWriter();
			PrincipalSerializer.serialize(pskIdentity, writer);

			// THEN the resulting byte array can be used to re-instantiate
			// the identity
			PreSharedKeyIdentity identity = (PreSharedKeyIdentity) PrincipalSerializer.deserialize(new DatagramReader(writer.toByteArray()));
			assertThat(identity, is(pskIdentity));
		} catch (GeneralSecurityException e) {
			// should not happen
			fail(e.getMessage());
		}
	}

	/**
	 * Verifies that a public key that has been serialized using the
	 * serialize method can be re-instantiated properly using the deserialize
	 * method.
	 * 
	 * @throws GeneralSecurityException if the key cannot be deserialized.
	 */
	@Test
	public void testSerializedRPKCanBeDeserialized() throws GeneralSecurityException {

		RawPublicKeyIdentity rpkIdentity = new RawPublicKeyIdentity(publicKey);

		// WHEN serializing the raw public key identity to a byte array
		DatagramWriter writer = new DatagramWriter();
		PrincipalSerializer.serialize(rpkIdentity, writer);

		// THEN the resulting byte array can be used to re-instantiate
		// the public key
		RawPublicKeyIdentity identity = (RawPublicKeyIdentity) PrincipalSerializer.deserialize(new DatagramReader(writer.toByteArray()));
		assertThat(identity.getKey(), is(publicKey));
		assertThat(identity.getKey().getAlgorithm(), is(publicKey.getAlgorithm()));
	}

	/**
	 * Verifies that a X509CertPath that has been serialized using the serialize
	 * method can be re-instantiated properly using the deserialize method.
	 * 
	 * @throws GeneralSecurityException if the X509CertPath cannot be
	 *             deserialized.
	 */
	@Test
	public void testSerializedX509CertPathCanBeDeserialized() throws GeneralSecurityException {
		X509CertPath x509Identity = X509CertPath.fromCertificatesChain(certificateChain);

		// WHEN serializing the X509CertPath to a byte array
		DatagramWriter writer = new DatagramWriter();
		PrincipalSerializer.serialize(x509Identity, writer);

		// THEN the resulting byte array can be used to re-instantiate
		// the X509CertPath
		X509CertPath identity = (X509CertPath) PrincipalSerializer
				.deserialize(new DatagramReader(writer.toByteArray()));
		assertThat(identity.getName(), is(x509Identity.getName()));
		assertThat(identity.getTarget(), is(x509Identity.getTarget()));
		assertThat(identity.getPath(), is(x509Identity.getPath()));
	}

}
