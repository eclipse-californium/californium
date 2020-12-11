/*******************************************************************************
 * Copyright 2018 University of Rostock, Institute of Applied Microelectronics and Computer Engineering
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
 *    Vikram (University of Rostock)- Initial creation, adapted from ECDHServerKeyExchangeTest
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class EcdhPskClientKeyExchangeTest {

	EcdhPskClientKeyExchange msg;
	byte[] ephemeralKeyPointEncoded;
	PskPublicInformation identity;
	
	@Before
	public void setUp() throws Exception {

		SupportedGroup usableGroup = SupportedGroup.secp256r1;
		XECDHECryptography ecdhe = new XECDHECryptography(usableGroup);
		msg = new EcdhPskClientKeyExchange(new PskPublicInformation("ID"), ecdhe.getEncodedPoint());
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
		HandshakeParameter parameter = new HandshakeParameter(KeyExchangeAlgorithm.ECDHE_PSK, CertificateType.X_509);
		EcdhPskClientKeyExchange handshakeMsg = DtlsTestTools.fromByteArray(serializedMsg, parameter);
		assertTrue(handshakeMsg.getIdentity().equals(identity));
		assertNotNull(ephemeralKeyPointEncoded);
		assertArrayEquals(handshakeMsg.getEncodedPoint(), ephemeralKeyPointEncoded);
	}
}
