/*******************************************************************************
 * Copyright (c) 2015, 2016 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use DtlsTestTools' accessors to explicitly retrieve
 *                                                    client & server keys and certificate chains
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use SessionListener to trigger sending of pending
 *                                                    APPLICATION messages
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class ClientHandshakerTest {

	final static int MAX_TRANSMISSION_UNIT = 1500;

	ClientHandshaker handshaker;
	InetSocketAddress peerAddress;
	SimpleRecordLayer recordLayer;

	@Before
	public void setUp() throws Exception {
		peerAddress = new InetSocketAddress(InetAddress.getLocalHost(), 0);
		recordLayer = new SimpleRecordLayer();
	}

	/**
	 * Assert that the <em>CLIENT_HELLO</em> message created by the handshaker
	 * contains a preference for RawPublicKeys only if no <em>trusted root certificates</em>
	 * have been configured.
	 */
	@Test
	public void testClientHelloContainsCorrectServerCertTypePreference() throws Exception {
		givenAClientHandshaker(true);
		handshaker.startHandshake();
		ClientHello clientHello = getClientHello(recordLayer.getSentFlight());
		assertPreferredServerCertificateExtension(clientHello, CertificateType.X_509);

		givenAClientHandshaker(false);
		handshaker.startHandshake();
		clientHello = getClientHello(recordLayer.getSentFlight());
		assertPreferredServerCertificateExtension(clientHello, CertificateType.RAW_PUBLIC_KEY);
	}

	private void givenAClientHandshaker(boolean configureTrustStore) throws Exception {
		DtlsConnectorConfig.Builder builder = 
				new DtlsConnectorConfig.Builder(new InetSocketAddress(InetAddress.getLocalHost(), 0))
					.setIdentity(
						DtlsTestTools.getClientPrivateKey(),
						DtlsTestTools.getClientCertificateChain(),
						false);

		if (configureTrustStore) {
			builder.setTrustStore(DtlsTestTools.getTrustedCertificates());
		}

		handshaker = new ClientHandshaker(
				new DTLSSession(peerAddress, true),
				recordLayer,
				null,
				builder.build(),
				MAX_TRANSMISSION_UNIT);
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
