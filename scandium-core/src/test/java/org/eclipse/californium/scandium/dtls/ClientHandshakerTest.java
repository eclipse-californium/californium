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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix 475112
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use ephemeral ports in endpoint addresses
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class ClientHandshakerTest {

	ClientHandshaker handshaker;
	InetSocketAddress peerAddress;

	@Before
	public void setUp() throws Exception {
		peerAddress = new InetSocketAddress(InetAddress.getLocalHost(), 0);
	}

	/**
	 * Assert that the <em>CLIENT_HELLO</em> message created by the handshaker
	 * contains a preference for RawPublicKeys only if no <em>trusted root certificates</em>
	 * have been configured.
	 */
	@Test
	public void testClientHelloContainsCorrectServerCertTypePreference() throws Exception {
		givenAClientHandshaker(true);
		ClientHello clientHello = getClientHello(handshaker.getStartHandshakeMessage());
		assertPreferredServerCertificateExtension(clientHello, CertificateType.X_509);

		givenAClientHandshaker(false);
		clientHello = getClientHello(handshaker.getStartHandshakeMessage());
		assertPreferredServerCertificateExtension(clientHello, CertificateType.RAW_PUBLIC_KEY);
	}

	private void givenAClientHandshaker(boolean configureTrustStore) throws Exception {
		DtlsConnectorConfig.Builder builder = 
				new DtlsConnectorConfig.Builder(new InetSocketAddress(InetAddress.getLocalHost(), 0))
					.setIdentity(
						DtlsTestTools.getPrivateKey(),
						DtlsTestTools.getCertificateChainFromStore(
											DtlsTestTools.KEY_STORE_LOCATION,
											DtlsTestTools.KEY_STORE_PASSWORD,
											DtlsTestTools.CLIENT_NAME),
						false);

		if (configureTrustStore) {
			builder.setTrustStore(DtlsTestTools.getTrustedCertificates());
		}

		handshaker = new ClientHandshaker(
				new RawData(new byte[]{}, peerAddress),
				new DTLSSession(peerAddress, true),
				null,
				builder.build());
	}

	private void assertPreferredServerCertificateExtension(ClientHello msg, CertificateType expectedType) {
		assertThat(msg.getServerCertificateTypeExtension(), notNullValue());
		assertThat(
			msg.getServerCertificateTypeExtension().getCertificateTypes().get(0),
			is(expectedType));
	}

	private ClientHello getClientHello(DTLSFlight flight) throws GeneralSecurityException, HandshakeException {
		Record record = flight.getMessages().get(0);
		return (ClientHello) record.getFragment();
	}
}
