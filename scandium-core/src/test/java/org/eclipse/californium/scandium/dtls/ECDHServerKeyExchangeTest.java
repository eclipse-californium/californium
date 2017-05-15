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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.junit.Assert.*;

import java.net.InetSocketAddress;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm.SignatureAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography.SupportedGroup;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class ECDHServerKeyExchangeTest {

	ECDHServerKeyExchange msg;
	InetSocketAddress peerAddress = new InetSocketAddress(5000);

	@Before
	public void setUp() throws Exception {

		SupportedGroup usableGroup = SupportedGroup.getUsableGroups()[0];
		msg = new ECDHServerKeyExchange(
				new SignatureAndHashAlgorithm(SignatureAndHashAlgorithm.HashAlgorithm.SHA256, SignatureAndHashAlgorithm.SignatureAlgorithm.ECDSA),
				ECDHECryptography.fromNamedCurveId(usableGroup.getId()),
				DtlsTestTools.getPrivateKey(),
				new Random(),
				new Random(),
				usableGroup.getId(),
				peerAddress);
	}

	@Test
	public void testInstanceToString() {
		String toString = msg.toString();
		assertNotNull(toString);
	}

	@Test
	public void testDeserializedInstanceToString() throws HandshakeException {
		byte[] serializedMsg = msg.toByteArray();
		HandshakeMessage handshakeMsg = HandshakeMessage.fromByteArray(
				serializedMsg, KeyExchangeAlgorithm.EC_DIFFIE_HELLMAN, true, peerAddress);
		assertNotNull(handshakeMsg.toString());
	}
}
