/*******************************************************************************
 * Copyright (c) 2015 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import java.security.PrivateKey;
import java.util.Arrays;

import static org.junit.Assert.assertNotNull;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
@Category(Small.class)
public class ECDHServerKeyExchangeTest {

	@Parameterized.Parameter
	public PrivateKey privateKey;

	EcdheServerKeyExchange msg;

	@Parameterized.Parameters(name = "privateKey = {index}")
	public static Iterable<PrivateKey> privateKeys() {
		return Arrays.asList(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerRsPrivateKey());
	}

	@Before
	public void setUp() throws Exception {

		SupportedGroup usableGroup = SupportedGroup.getUsableGroups().get(0);
		msg = new EcdheServerKeyExchange(
				new SignatureAndHashAlgorithm(SignatureAndHashAlgorithm.HashAlgorithm.SHA256, SignatureAndHashAlgorithm.SignatureAlgorithm.ECDSA),
				new XECDHECryptography(usableGroup),
				privateKey,
				new Random(),
				new Random());
	}

	@Test
	public void testInstanceToString() {
		String toString = msg.toString();
		assertNotNull(toString);
	}

	@Test
	public void testDeserializedInstanceToString() throws HandshakeException {
		byte[] serializedMsg = msg.toByteArray();
		HandshakeParameter parameter = new HandshakeParameter(KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, CertificateType.RAW_PUBLIC_KEY);

		HandshakeMessage handshakeMsg = DtlsTestTools.fromByteArray(serializedMsg, parameter);

		assertNotNull(handshakeMsg.toString());
	}
}
