package org.eclipse.californium.scandium.dtls;

import static org.junit.Assert.*;

import java.net.InetSocketAddress;

import org.eclipse.californium.scandium.dtls.CertificateRequest.HashAlgorithm;
import org.eclipse.californium.scandium.dtls.CertificateRequest.SignatureAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.ECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.junit.Before;
import org.junit.Test;

public class ECDHServerKeyExchangeTest {

	ECDHServerKeyExchange msg;
	InetSocketAddress peerAddress = new InetSocketAddress(5000);
	@Before
	public void setUp() throws Exception {
		
		msg = new ECDHServerKeyExchange(
				new SignatureAndHashAlgorithm(HashAlgorithm.SHA256, SignatureAlgorithm.ECDSA),
				new ECDHECryptography(23),
				DtlsTestTools.getPrivateKey(),
				new Random(),
				new Random(),
				23,
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
