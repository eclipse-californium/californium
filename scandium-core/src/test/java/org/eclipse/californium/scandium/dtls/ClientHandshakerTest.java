/*******************************************************************************
 * Copyright (c) 2015, 2018 Bosch Software Innovations GmbH and others.
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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.TestScheduledExecutorService;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier.Builder;
import org.eclipse.californium.scandium.util.ServerName.NameType;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of the {@code ClientHandshaker}.
 *
 */
@Category(Small.class)
public class ClientHandshakerTest {

	final static int MAX_TRANSMISSION_UNIT = 1500;

	@Rule
	public ThreadsRule cleanup = new ThreadsRule();

	final InetSocketAddress localPeer = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
	final SimpleRecordLayer recordLayer = new SimpleRecordLayer();
	final String serverName = "iot.eclipse.org";

	ClientHandshaker handshaker;
	ScheduledExecutorService timer;

	@Before
	public void setup() {
		timer = new TestScheduledExecutorService();
	}

	@After
	public void tearDown() {
		timer.shutdown();
		timer = null;
	}

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

	@Test
	public void testClientReceivesBrokenServerHello() throws Exception {

		givenAClientHandshaker(false);

		// WHEN a handshake is started
		handshaker.startHandshake();

		// THEN assert that the sent client hello contains an SNI extension
		ClientHello clientHello = getClientHello(recordLayer.getSentFlight());
		assertNotNull(clientHello);
		CipherSuite cipherSuite = clientHello.getCipherSuites().get(0);
		HelloExtensions extensions = new HelloExtensions();
		extensions.addExtension(ConnectionIdExtension.fromConnectionId(ConnectionId.EMPTY));
		ServerHello serverHello = new ServerHello(clientHello.getClientVersion(), new Random(), new SessionId(),
				cipherSuite, CompressionMethod.NULL, extensions, localPeer);
		Record record =  DtlsTestTools.getRecordForMessage(0, 1, serverHello, localPeer);
		record.applySession(handshaker.session);
		try {
			handshaker.processMessage(record);
			fail("Broken SERVER_HELLO not detected!");
		} catch (HandshakeException ex) {
			assertThat(ex.getAlert().getLevel(), is(AlertLevel.FATAL));
			assertThat(ex.getAlert().getDescription(), is(AlertDescription.UNSUPPORTED_EXTENSION));
		}
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
				DtlsConnectorConfig.builder()
					.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
					.setIdentity(
						DtlsTestTools.getClientPrivateKey(),
						DtlsTestTools.getClientCertificateChain(),
						CertificateType.X_509)
					.setSniEnabled(sniEnabled);

		Builder verifierBuilder = StaticNewAdvancedCertificateVerifier.builder();
		if (configureTrustStore) {
			builder.setAdvancedCertificateVerifier(verifierBuilder.setTrustedCertificates(DtlsTestTools.getTrustedCertificates()).build());
		} else if (configureEmptyTrustStore) {
			builder.setAdvancedCertificateVerifier(verifierBuilder.setTrustAllCertificates().build());
		} else if (configureRpkTrustAll) {
			builder.setAdvancedCertificateVerifier(verifierBuilder.setTrustAllRPKs().build());
		} else {
			builder.setClientAuthenticationRequired(false);
		}
		Connection connection = new Connection(peer, new SyncSerialExecutor());
		DTLSSession session = new DTLSSession(peer);
		session.setHostName(virtualHost);
		handshaker = new ClientHandshaker(
				session,
				recordLayer,
				timer,
				connection,
				builder.build(),
				false);
		recordLayer.setHandshaker(handshaker);
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

	private static ClientHello getClientHello(List<Record> flight) throws GeneralSecurityException, HandshakeException {
		Record record = flight.get(0);
		return (ClientHello) record.getFragment();
	}
}
