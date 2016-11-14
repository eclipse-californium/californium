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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 464383
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix 464812
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for stale
 *                                                    session expiration (466554)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace SessionStore with ConnectionStore
 *                                                    keeping all information about the connection
 *                                                    to a peer in a single place
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 472196
 *    Achim Kraus, Kai Hudalla (Bosch Software Innovations GmbH) - add test case for bug 478538
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use DtlsTestTools' accessors to explicitly retrieve
 *                                                    client & server keys and certificate chains
 *    Bosch Software Innovations GmbH - add test cases for GitHub issue #1
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.scandium.ConnectorHelper.LatchDecrementingRawDataChannel;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.ServerNameResolver;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.eclipse.californium.scandium.util.ServerName;
import org.eclipse.californium.scandium.util.ServerNames;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * A set of integration tests verifying the handling of hello extensions.
 *
 */
@Category(Medium.class)
public class HelloExtensionNegotiationTest {

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;

	static ConnectorHelper serverHelper;

	DtlsConnectorConfig clientConfig;
	DTLSConnector client;
	InetSocketAddress clientEndpoint;
	LatchDecrementingRawDataChannel clientRawDataChannel;
	DTLSSession establishedServerSession;
	DTLSSession establishedClientSession;
	InMemoryConnectionStore clientConnectionStore;

	/**
	 * Configures and starts a server side connector for running the tests against.
	 * 
	 * @throws IOException if the key store to read the server's keys from cannot be found.
	 * @throws GeneralSecurityException if the server's keys cannot be read.
	 */
	@BeforeClass
	public static void startServer() throws IOException, GeneralSecurityException {

		serverHelper = new ConnectorHelper();
		serverHelper.startServer();
	}

	/**
	 * Shuts down and destroys the sever side connector.
	 */
	@AfterClass
	public static void tearDown() {
		serverHelper.destroyServer();
	}

	/**
	 * Creates a client side connector to run tests with.
	 * @throws GeneralSecurityException 
	 * @throws IOException 
	 * 
	 * @throws IOException if the key store to read the client's keys from cannot be found.
	 * @throws GeneralSecurityException if the client's keys cannot be read.
	 */
	@Before
	public void setUpClient() throws IOException, GeneralSecurityException {

		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);
		clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		clientConfig = ConnectorHelper.newStandardClientConfig(clientEndpoint);

		client = new DTLSConnector(clientConfig, clientConnectionStore);

		clientRawDataChannel = serverHelper.new LatchDecrementingRawDataChannel();
	}

	/**
	 * Destroys client and re-sets server to inital state. 
	 */
	@After
	public void cleanUp() {
		if (client != null) {
			client.destroy();
		}
		serverHelper.cleanUpServer();
	}

	/**
	 * Verifies that the connector includes server names provided by a client in a 
	 * <em>Server Name Indication</em> hello extension in the <code>RawData</code> object
	 * passed to the application layer.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testConnectorForwardsServerNamesToApplication() throws Exception {

		final String hostName = "iot.eclipse.org";
		final ServerNames serverNames = ServerNames.newInstance(ServerName.fromHostName(hostName));

		// GIVEN a client configured to indicate server names to the server
		clientConfig = ConnectorHelper.newStandardClientConfigBuilder(clientEndpoint)
			.setPskStore(new StaticPskStore(ConnectorHelper.CLIENT_IDENTITY, ConnectorHelper.CLIENT_IDENTITY_SECRET.getBytes()))
			.setServerNameResolver(new ServerNameResolver() {

				@Override
				public ServerNames getServerNames(final InetSocketAddress peerAddress) {
					return serverNames;
				}
			})
			.build();
		client = new DTLSConnector(clientConfig, clientConnectionStore);

		// WHEN a session has been established
		serverHelper.givenAnEstablishedSession(client);

		// THEN assert that the application layer is notified about the server names provided by the client
		assertHostNameIsForwardedToApplicationLayer(hostName);
	}

	private static void assertHostNameIsForwardedToApplicationLayer(final String hostName) {

		RawData msg = serverHelper.serverRawDataProcessor.getLatestInboundMessage();
		assertNotNull(msg);

		String value = msg.getCorrelationContext().get(DTLSConnector.KEY_TLS_SERVER_HOST_NAME);
		assertThat(value, is(hostName));
	}

	/**
	 * Verifies that negotiation of the maximum fragment length to use in a DTLS
	 * connection works.
	 * 
	 * @throws Exception if the test fails.
	 */
	@Test
	public void testConnectorNegotiatesMaxFragmentLength() throws Exception {
		// given a constrained client that can only handle fragments of max. 512 bytes
		clientConfig = ConnectorHelper.newStandardClientConfigBuilder(clientEndpoint)
				.setMaxFragmentLengthCode(1)
				.build();
		client = new DTLSConnector(clientConfig, clientConnectionStore);

		// when the client negotiates a session with the server
		serverHelper.givenAnEstablishedSession(client, false);

		// then any message sent by either the client or server contains at most
		// 512 bytes of payload data
		assertThat(client.getMaximumFragmentLength(serverHelper.serverEndpoint), is(512));
		assertThat(serverHelper.server.getMaximumFragmentLength(client.getAddress()), is(512));
	}


}
