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
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;

import org.eclipse.californium.scandium.ConnectorHelper.LatchDecrementingRawDataChannel;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * A set of integration tests verifying the handling of hello extensions.
 *
 */
@Category(Medium.class)
public class HelloExtensionNegotiationTest {
	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT, DtlsNetworkRule.Mode.NATIVE);

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
	 * Destroys client and re-sets server to initial state.
	 */
	@After
	public void cleanUp() {
		if (client != null) {
			client.destroy();
		}
		serverHelper.cleanUpServer();
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
