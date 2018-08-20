/*******************************************************************************
 * Copyright 2018 University of Rostock, Institute of Applied Microelectronics and Computer Engineering
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
 *    Vikram (University of Rostock)- Initial creation, adapted from ECDHServerKeyExchangeTest
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.InetSocketAddress;
import java.util.Arrays;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography.SupportedGroup;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class EcdhPskClientKeyExchangeTest {

	EcdhPskClientKeyExchange msg;
	InetSocketAddress peerAddress = new InetSocketAddress(5000);
	byte[] ephemeralKeyPointEncoded;
	String identity;
	
	@Before
	public void setUp() throws Exception {

		SupportedGroup usableGroup = SupportedGroup.secp256r1;
		ECDHECryptography ecdhe = ECDHECryptography.fromNamedCurveId(usableGroup.getId());
		msg = new EcdhPskClientKeyExchange("ID", ecdhe.getPublicKey(), peerAddress);
		ephemeralKeyPointEncoded = msg.getEncodedPoint();
		identity = msg.getIdentity();
	}
	
	@Test
	public void testInstanceToString() {
		String toString = msg.toString();
		assertNotNull(toString);
	}

	@Test
	public void testDeserializedMsg() throws HandshakeException {
		byte[] serializedMsg = msg.toByteArray();
		HandshakeParameter parameter = new HandshakeParameter(KeyExchangeAlgorithm.ECDHE_PSK, false);
		HandshakeMessage handshakeMsg = HandshakeMessage.fromByteArray(serializedMsg, parameter, peerAddress);
		assertTrue(((EcdhPskClientKeyExchange)handshakeMsg).getIdentity().equals(identity));
		assertNotNull(ephemeralKeyPointEncoded);
		assertTrue((Arrays.equals(((EcdhPskClientKeyExchange)handshakeMsg).getEncodedPoint(), ephemeralKeyPointEncoded)));
	}
}
