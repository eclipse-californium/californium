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
 *    Achim Kraus (Bosch Software Innovations GmbH) - Replace getLocalHost() by
 *                                                    getLoopbackAddress()
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateTypeExtension.CertificateType;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerName.NameType;
import org.eclipse.californium.scandium.util.ServerNames;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of the {@code ClientHandshaker}.
 *
 */
@Category(Small.class)
public class ClientHandshakerTest {

	final static int MAX_TRANSMISSION_UNIT = 1500;

	final InetSocketAddress localPeer = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
	final SimpleRecordLayer recordLayer = new SimpleRecordLayer();
	final byte[] serverName = "iot.eclipse.org".getBytes(StandardCharsets.US_ASCII);

	ClientHandshaker handshaker;

	/**
	 * Assert that the <em>CLIENT_HELLO</em> message created by the handshaker
	 * contains a preference for X.509 certificates if <em>trusted root certificates</em>
	 * have been configured.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testServerCertExtPrefersX509WithTrustStore() throws Exception {

		givenAClientHandshaker(true);
		handshaker.startHandshake();
		ClientHello clientHello = getClientHello(recordLayer.getSentFlight());
		assertPreferredServerCertificateExtension(clientHello, CertificateType.X_509);
	}

	/**
	 * Assert that the <em>CLIENT_HELLO</em> message created by the handshaker
	 * contains a preference for RawPublicKeys if no <em>trusted root certificates</em>
	 * have been configured.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testServerCertExtPrefersRawPublicKeysWithoutTrustStore() throws Exception {

		givenAClientHandshaker(false);
		handshaker.startHandshake();
		ClientHello clientHello = getClientHello(recordLayer.getSentFlight());
		assertPreferredServerCertificateExtension(clientHello, CertificateType.RAW_PUBLIC_KEY);
	}

	/**
	 * Asserts that the <em>Client_HELLO</em> message created by the handshaker does not contain
	 * a <em>Server Name Indication</em> extension when no server names have been configured
	 * for a peer.
	 * 
	 * @throws Exception if test fails.
	 */
	@Test
	public void testClientHelloLacksServerNameExtensionForNonRegisteredPeer() throws Exception {

		givenAClientHandshaker(new InetSocketAddress(InetAddress.getByAddress(new byte[]{10, 0, 0, 1}), 10000), false);

		// WHEN a handshake is started with the peer
		handshaker.startHandshake();

		// THEN assert that the sent client hello does not contain an SNI extension
		ClientHello clientHello = getClientHello(recordLayer.getSentFlight());
		assertNull(clientHello.getServerNameExtension());
	}

	/**
	 * Asserts that the <em>Client_HELLO</em> message created by the handshaker contains
	 * a <em>Server Name Indication</em> extension when server names have been configured
	 * for a peer.
	 * @throws Exception 
	 */
	@Test
	public void testClientHelloContainsServerNameExtensionForRegisteredPeer() throws Exception {

		givenAClientHandshaker(false);

		// WHEN a handshake is started
		handshaker.startHandshake();

		// THEN assert that the sent client hello contains an SNI extension
		ClientHello clientHello = getClientHello(recordLayer.getSentFlight());
		assertNotNull(clientHello.getServerNameExtension());
		assertThat(
				clientHello.getServerNameExtension().getServerNames().get(NameType.HOST_NAME),
				is(serverName));
	}

	private void givenAClientHandshaker(final boolean configureTrustStore) throws Exception {
		givenAClientHandshaker(localPeer, configureTrustStore);
	}

	private void givenAClientHandshaker(final InetSocketAddress peer, final boolean configureTrustStore) throws Exception {
		DtlsConnectorConfig.Builder builder = 
				new DtlsConnectorConfig.Builder(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
					.setIdentity(
						DtlsTestTools.getClientPrivateKey(),
						DtlsTestTools.getClientCertificateChain(),
						false)
					.setServerNameResolver(new ServerNameResolver() {

						@Override
						public ServerNames getServerNames(final InetSocketAddress address) {
							if (localPeer.equals(address)) {
								return ServerNames.newInstance(ServerName.from(NameType.HOST_NAME, serverName));
							} else {
								return null;
							}
						}
					});

		if (configureTrustStore) {
			builder.setTrustStore(DtlsTestTools.getTrustedCertificates());
		}

		handshaker = new ClientHandshaker(
				new DTLSSession(peer, true),
				recordLayer,
				null,
				builder.build(),
				MAX_TRANSMISSION_UNIT);
	}

	private static void assertPreferredServerCertificateExtension(final ClientHello msg, final CertificateType expectedType) {
		assertThat(msg.getServerCertificateTypeExtension(), notNullValue());
		assertThat(
			msg.getServerCertificateTypeExtension().getCertificateTypes().get(0),
			is(expectedType));
	}

	private static ClientHello getClientHello(final DTLSFlight flight) throws GeneralSecurityException, HandshakeException {
		Record record = flight.getMessages().get(0);
		return (ClientHello) record.getFragment();
	}
}
