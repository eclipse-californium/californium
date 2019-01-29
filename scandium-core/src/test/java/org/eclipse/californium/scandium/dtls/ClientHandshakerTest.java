/*******************************************************************************
 * Copyright (c) 2015, 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - issue #549
 *                                                    add testServerCertExtPrefersX509WithEmptyTrustStore
 *                                                    trustStore := null, disable x.509
 *                                                    trustStore := [], enable x.509, trust all
 *    Achim Kraus (Bosch Software Innovations GmbH) - Replace getLocalHost() by
 *                                                    getLoopbackAddress()
 ******************************************************************************/
package org.eclipse.californium.scandium.dtls;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;

import org.eclipse.californium.scandium.category.Small;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.util.ServerName.NameType;
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
	final String serverName = "iot.eclipse.org";

	ClientHandshaker handshaker;

	/**
	 * Assert that the <em>CLIENT_HELLO</em> message created by the handshaker
	 * contains a preference for X.509 certificates if <em>trusted root certificates</em>
	 * have been configured.
	 * 
	 * @throws Exception if the handshake cannot be started.
	 */
	@Test
	public void testServerCertExtPrefersX509WithTrustStore() throws Exception {

		givenAClientHandshaker(true);
		handshaker.startHandshake();
		ClientHello clientHello = getClientHello(recordLayer.getSentFlight());
		assertPreferredServerCertificateExtension(clientHello, CertificateType.X_509);
	}

	/**
	 * Verifies that the <em>CLIENT_HELLO</em> message created by the handshaker
	 * includes a server certificate extension which indicates a preference for
	 * X.509 certificates when an empty trust store is configured.
	 * 
	 * @throws Exception if the handshake cannot be started.
	 */
	@Test
	public void testServerCertExtPrefersX509WithEmptyTrustStore() throws Exception {

		givenAClientHandshaker(localPeer, false, true);
		handshaker.startHandshake();
		ClientHello clientHello = getClientHello(recordLayer.getSentFlight());
		assertPreferredServerCertificateExtension(clientHello, CertificateType.X_509);
	}

	/**
	 * Assert that the <em>CLIENT_HELLO</em> message created by the handshaker
	 * contains a preference for RawPublicKeys if no <em>trusted root certificates</em>
	 * have been configured.
	 * 
	 * @throws Exception if the handshake cannot be started.
	 */
	@Test
	public void testServerCertExtPrefersRawPublicKeysWithoutTrustStore() throws Exception {

		givenAClientHandshaker(localPeer, null, false, false, true, false);
		handshaker.startHandshake();
		ClientHello clientHello = getClientHello(recordLayer.getSentFlight());
		assertPreferredServerCertificateExtension(clientHello, CertificateType.RAW_PUBLIC_KEY);
	}

	/**
	 * Asserts that the <em>Client_HELLO</em> message created by the handshaker does not contain
	 * a <em>Server Name Indication</em> extension when the negotiating a session with a
	 * peer identified by socket address only.
	 * 
	 * @throws Exception if the handshake cannot be started.
	 */
	@Test
	public void testClientHelloLacksServerNameExtensionForMessageWithoutVirtualHost() throws Exception {

		givenAClientHandshaker(null, false);

		// WHEN a handshake is started with the peer
		handshaker.startHandshake();

		// THEN assert that the sent client hello does not contain an SNI extension
		ClientHello clientHello = getClientHello(recordLayer.getSentFlight());
		assertNull(clientHello.getServerNameExtension());
	}

	/**
	 * Asserts that the <em>Client_HELLO</em> message created by the handshaker does not contain
	 * a <em>Server Name Indication</em> extension when negotiating a session with a virtual host
	 * but with SNI disabled.
	 * 
	 * @throws Exception if the handshake cannot be started.
	 */
	@Test
	public void testClientHelloLacksServerNameExtensionForDisabledSni() throws Exception {

		// GIVEN a handshaker for a virtual host but with SNI disabled
		givenAClientHandshaker(localPeer, serverName, false, false, false, false);

		// WHEN a handshake is started with the peer
		handshaker.startHandshake();

		// THEN assert that the sent client hello does not contain an SNI extension
		ClientHello clientHello = getClientHello(recordLayer.getSentFlight());
		assertNull(clientHello.getServerNameExtension());
	}

	/**
	 * Asserts that the <em>Client_HELLO</em> message created by the handshaker contains
	 * a <em>Server Name Indication</em> extension when negotiating a session with a virtual host
	 * at the peer.
	 * 
	 * @throws Exception if the handshake cannot be started.
	 */
	@Test
	public void testClientHelloContainsServerNameExtensionForMessageWithVirtualHost() throws Exception {

		givenAClientHandshaker(serverName, false);

		// WHEN a handshake is started
		handshaker.startHandshake();

		// THEN assert that the sent client hello contains an SNI extension
		ClientHello clientHello = getClientHello(recordLayer.getSentFlight());
		assertNotNull(clientHello.getServerNameExtension());
		assertThat(
				clientHello.getServerNameExtension().getServerNames().getServerName(NameType.HOST_NAME).getNameAsString(),
				is(serverName));
	}

	private void givenAClientHandshaker(final boolean configureTrustStore) throws Exception {
		givenAClientHandshaker(null, configureTrustStore);
	}

	private void givenAClientHandshaker(final String virtualHost, final boolean configureTrustStore) throws Exception {
		givenAClientHandshaker(localPeer, virtualHost, configureTrustStore, false, false, true);
	}

	private void givenAClientHandshaker(final InetSocketAddress peer, final boolean configureTrustStore, final boolean configureEmptyTrustStore) throws Exception {
		givenAClientHandshaker(peer, serverName, configureTrustStore, configureEmptyTrustStore, false, true);
	}

	private void givenAClientHandshaker(
			final InetSocketAddress peer,
			final String virtualHost,
			final boolean configureTrustStore,
			final boolean configureEmptyTrustStore,
			final boolean configureRpkTrustAll,
			final boolean sniEnabled) throws Exception {

		DtlsConnectorConfig.Builder builder = 
				new DtlsConnectorConfig.Builder()
					.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
					.setIdentity(
						DtlsTestTools.getClientPrivateKey(),
						DtlsTestTools.getClientCertificateChain(),
						CertificateType.X_509)
					.setSniEnabled(sniEnabled);

		if (configureTrustStore) {
			builder.setTrustStore(DtlsTestTools.getTrustedCertificates());
		} else if (configureEmptyTrustStore) {
			builder.setTrustStore(new Certificate[0]);
		} else if (configureRpkTrustAll) {
			builder.setRpkTrustAll();
		} else {
			builder.setClientAuthenticationRequired(false);
		}
		DTLSSession session = new DTLSSession(peer);
		session.setVirtualHost(virtualHost);
		handshaker = new ClientHandshaker(
				session,
				recordLayer,
				null,
				builder.build(),
				MAX_TRANSMISSION_UNIT);
	}

	private static void assertPreferredServerCertificateExtension(final ClientHello msg, final CertificateType expectedType) {
		CertificateType preferred = null;
		ServerCertificateTypeExtension typeExtension = msg.getServerCertificateTypeExtension();
		if (typeExtension != null) {
			preferred = typeExtension.getCertificateTypes().get(0);
		}
		if (expectedType == CertificateType.X_509) {
			if (preferred == null) {
				return;
			}
		}
		else {
			assertThat(typeExtension, notNullValue());
		}
		assertThat(preferred, is(expectedType));
	}

	private static ClientHello getClientHello(final DTLSFlight flight) throws GeneralSecurityException, HandshakeException {
		Record record = flight.getMessages().get(0);
		return (ClientHello) record.getFragment();
	}
}
