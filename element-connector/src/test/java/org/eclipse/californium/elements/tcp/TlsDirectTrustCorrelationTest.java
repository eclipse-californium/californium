/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation. 
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.tcp.ConnectorTestUtil.SSLTestContext;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;

public class TlsDirectTrustCorrelationTest {

	@Rule
	public final Timeout timeout = new Timeout(10, TimeUnit.SECONDS);
	private final List<Connector> cleanup = new ArrayList<>();

	@BeforeClass
	public static void initializeSsl() throws Exception {
		ConnectorTestUtil.initializeSsl();
	}

	@After
	public void cleanup() {
		for (Connector connector : cleanup) {
			connector.stop();
		}
	}

	@Test
	public void serverSideClientPrincipal() throws Exception {
		SSLTestContext serverContext = DirectTrustConnectorTestUtil.initializeDirectTrustedContext(
				ConnectorTestUtil.SERVER_NAME, DirectTrustConnectorTestUtil.CLIENT_NAME_PATTERN);

		TlsServerConnector server = new TlsServerConnector(serverContext.context, new InetSocketAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(ConnectorTestUtil.clientContext,
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.CONECTION_TIMEOUT_IN_MS,
				ConnectorTestUtil.IDLE_TIMEOUT_IN_S);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		RawData msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, null);

		client.send(msg);
		serverCatcher.blockUntilSize(1, 2000);
		assertThat(serverCatcher.hasMessage(0), is(true));
		RawData receivedMessage = serverCatcher.getMessage(0);
		assertThat(receivedMessage, is(notNullValue()));
		assertThat(receivedMessage.getSenderIdentity(), is(ConnectorTestUtil.clientSubjectDN));
	}

	@Test
	public void serverSideDoesntTrustClient() throws Exception {
		/* server doesn't trust client */
		SSLTestContext serverContext = DirectTrustConnectorTestUtil.initializeDirectTrustedContext(
				ConnectorTestUtil.SERVER_NAME, ConnectorTestUtil.NO_TRUST_NAME);

		TlsServerConnector server = new TlsServerConnector(serverContext.context, new InetSocketAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(ConnectorTestUtil.clientContext,
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.CONECTION_TIMEOUT_IN_MS,
				ConnectorTestUtil.IDLE_TIMEOUT_IN_S);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		RawData msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, null);

		client.send(msg);
		serverCatcher.blockUntilSize(1, 2000);
		assertThat(serverCatcher.hasMessage(0), is(false));
		/*
		 * "direct-trust" MUST NOT supply issuer, therefore the client
		 * certificate failed to validate, even if only setWantClientAuth is
		 * used.
		 */
	}

	@Test
	public void clientSideServerPrincipal() throws Exception {
		SSLTestContext clientContext = DirectTrustConnectorTestUtil.initializeDirectTrustedContext(
				ConnectorTestUtil.CLIENT_NAME, ConnectorTestUtil.SERVER_NAME);

		TlsServerConnector server = new TlsServerConnector(ConnectorTestUtil.serverContext, new InetSocketAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(clientContext.context, ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		RawData msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, null);

		client.send(msg);
		serverCatcher.blockUntilSize(1, 2000);
		assertThat(serverCatcher.hasMessage(0), is(true));

		msg = ConnectorTestUtil.createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 100, null);
		server.send(msg);
		clientCatcher.blockUntilSize(1);

		RawData receivedMessage = clientCatcher.getMessage(0);
		assertThat(receivedMessage, is(notNullValue()));
		assertThat(receivedMessage.getSenderIdentity(), is(ConnectorTestUtil.serverSubjectDN));
	}

	@Test
	public void clientSideDoesntTrustServer() throws Exception {
		/* client doesn't trust server */
		SSLTestContext clientContext = DirectTrustConnectorTestUtil.initializeDirectTrustedContext(
				ConnectorTestUtil.CLIENT_NAME, ConnectorTestUtil.NO_TRUST_NAME);

		TlsServerConnector server = new TlsServerConnector(ConnectorTestUtil.serverContext, new InetSocketAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(clientContext.context, ConnectorTestUtil.NUMBER_OF_THREADS,
				ConnectorTestUtil.CONECTION_TIMEOUT_IN_MS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		RawData msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, null);

		client.send(msg);
		serverCatcher.blockUntilSize(1, 2000);
		assertThat(serverCatcher.hasMessage(0), is(false));
	}

}
