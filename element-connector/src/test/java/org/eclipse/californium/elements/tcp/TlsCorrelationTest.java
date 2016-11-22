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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.hamcrest.text.IsEmptyString.isEmptyOrNullString;
import static org.junit.Assert.assertTrue;

import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.TcpCorrelationContext;
import org.eclipse.californium.elements.TlsCorrelationContext;
import org.eclipse.californium.elements.tcp.ConnectorTestUtil.SSLTestContext;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.Timeout;

public class TlsCorrelationTest {

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
	public void correlationContext() throws Exception {
		TlsServerConnector server = new TlsServerConnector(ConnectorTestUtil.serverContext, new InetSocketAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(ConnectorTestUtil.clientContext,
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.CONECTION_TIMEOUT_IN_MS, 10);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);

		CorrelationContext context = clientCallback.getCorrelationContext();
		assertThat("no TLS Correlation Context", context, is(instanceOf(TlsCorrelationContext.class)));
		TlsCorrelationContext tlsContext = (TlsCorrelationContext) context;
		assertThat(tlsContext.getSessionId(), is(not(isEmptyOrNullString())));
		assertThat(tlsContext.getCipher(), is(not(isEmptyOrNullString())));

		// Response message must go over the same connection client already
		// opened
		SimpleMessageCallback serverCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil
				.createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 10000, serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(1);

		context = serverCallback.getCorrelationContext();
		assertThat("Serverside no TLS Correlation Context", context, is(instanceOf(TlsCorrelationContext.class)));
		TlsCorrelationContext serverSideContext = (TlsCorrelationContext) context;
		assertThat(serverSideContext.getSessionId(), is(tlsContext.getSessionId()));
		assertThat(serverSideContext.getCipher(), is(tlsContext.getCipher()));

		clientCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, clientCallback);
		client.send(msg);
		context = clientCallback.getCorrelationContext(ConnectorTestUtil.CONTEXT_TIMEOUT_IN_MS);
		assertTrue("no response TLS Correlation Context", context instanceof TlsCorrelationContext);
		TlsCorrelationContext tlsResponseContext = (TlsCorrelationContext) context;
		assertThat(tlsResponseContext.getSessionId(), is(tlsContext.getSessionId()));
		assertThat(tlsResponseContext.getCipher(), is(tlsContext.getCipher()));
		assertThat(tlsResponseContext, is(tlsContext));
	}

	@Test
	public void correlationContextReconnectTimeout() throws Exception {
		TlsServerConnector server = new TlsServerConnector(ConnectorTestUtil.serverContext, new InetSocketAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);
		TlsClientConnector client = new TlsClientConnector(ConnectorTestUtil.clientContext,
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.CONECTION_TIMEOUT_IN_MS,
				ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);

		CorrelationContext clientContext = clientCallback.getCorrelationContext();
		assertThat("no TLS Correlation Context", clientContext, is(instanceOf(TlsCorrelationContext.class)));

		// Response message must go over the same connection client already
		// opened
		SimpleMessageCallback serverCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 100, serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(1);

		CorrelationContext serverContext = serverCallback.getCorrelationContext();
		assertThat("Serverside no TLS Correlation Context", serverContext, is(instanceOf(TlsCorrelationContext.class)));

		// timeout connection, hopefully this triggers a reconnect
		Thread.sleep(TimeUnit.MILLISECONDS.convert(ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S * 2, TimeUnit.SECONDS));

		clientCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(2);

		CorrelationContext clientContextAfterReconnect = clientCallback.getCorrelationContext();
		assertThat("no TLS Correlation Context after reconnect", clientContextAfterReconnect,
				is(instanceOf(TlsCorrelationContext.class)));
		// new (different) client side connection
		assertThat(clientContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(clientContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));
		// the session may be resumed ... so the session id may be not renewed
		assertThat(clientContextAfterReconnect, is(not(clientContext)));

		// Response message must go over the reconnected connection
		serverCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(serverCatcher.getMessage(1).getInetSocketAddress(), 100, serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(2);

		CorrelationContext serverContextAfterReconnect = serverCallback.getCorrelationContext();
		assertThat("Serverside no TLS Correlation Context after reconnect", serverContextAfterReconnect,
				is(instanceOf(TlsCorrelationContext.class)));
		// new (different) server side connection
		assertThat(serverContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(serverContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));
		// the session may be resumed ... so the session id may be not renewed
		assertThat(serverContextAfterReconnect, is(not(serverContext)));

	}

	@Test
	public void correlationContextReconnectStopStart() throws Exception {
		TlsServerConnector server = new TlsServerConnector(ConnectorTestUtil.serverContext, new InetSocketAddress(0),
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);
		TlsClientConnector client = new TlsClientConnector(ConnectorTestUtil.clientContext,
				ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.CONECTION_TIMEOUT_IN_MS,
				ConnectorTestUtil.IDLE_TIMEOUT_RECONNECT_IN_S);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);

		CorrelationContext clientContext = clientCallback.getCorrelationContext();
		assertThat("no TLS Correlation Context", clientContext, is(instanceOf(TlsCorrelationContext.class)));

		// Response message must go over the same connection client already
		// opened
		SimpleMessageCallback serverCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 100, serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(1);

		CorrelationContext serverContext = serverCallback.getCorrelationContext();
		assertThat("Serverside no TLS Correlation Context", serverContext, is(instanceOf(TlsCorrelationContext.class)));

		server.stop();
		server.start();

		clientCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(2);

		CorrelationContext clientContextAfterReconnect = clientCallback.getCorrelationContext();
		assertThat("no TLS Correlation Context after reconnect", clientContextAfterReconnect,
				is(instanceOf(TlsCorrelationContext.class)));
		// new (different) client side connection
		assertThat(clientContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(clientContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));
		assertThat(clientContextAfterReconnect.get(CorrelationContext.KEY_SESSION_ID),
				is(not(clientContext.get(CorrelationContext.KEY_SESSION_ID))));
		assertThat(clientContextAfterReconnect, is(not(clientContext)));

		// Response message must go over the reconnected connection
		serverCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(serverCatcher.getMessage(1).getInetSocketAddress(), 100, serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(2);

		CorrelationContext serverContextAfterReconnect = serverCallback.getCorrelationContext();
		assertThat("Serverside no TLS Correlation Context after reconnect", serverContextAfterReconnect,
				is(instanceOf(TlsCorrelationContext.class)));
		// new (different) server side connection
		assertThat(serverContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(serverContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));
		assertThat(serverContextAfterReconnect.get(CorrelationContext.KEY_SESSION_ID),
				is(not(serverContext.get(CorrelationContext.KEY_SESSION_ID))));
		assertThat(serverContextAfterReconnect, is(not(serverContext)));

	}

	@Test
	public void serverSideClientPrincipal() throws Exception {
		TlsServerConnector server = new TlsServerConnector(ConnectorTestUtil.serverContext, new InetSocketAddress(0),
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
		serverCatcher.blockUntilSize(1);
		RawData receivedMessage = serverCatcher.getMessage(0);
		assertThat(receivedMessage, is(notNullValue()));
		assertThat(receivedMessage.getSenderIdentity(), is(ConnectorTestUtil.clientSubjectDN));
	}

	@Test
	public void serverSideDoesntTrustClientUsingWantClientAuth() throws Exception {
		/* server doesn't trust client. use different ca's for server side trust */
		SSLTestContext serverContext = ConnectorTestUtil.initializeNoTrustContext(ConnectorTestUtil.SERVER_NAME, null);
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
		serverCatcher.blockUntilSize(1);
		RawData receivedMessage = serverCatcher.getMessage(0);
		assertThat(receivedMessage, is(notNullValue()));
		assertThat(receivedMessage.getSenderIdentity(), is(nullValue()));
		/*
		 * If issuer are supplied by the server, the client doesn't provide a
		 * certificate, if setWantClientAuth is used and no certificate is
		 * signed by a provided issuer. Therefore the connection is established.
		 */
	}

	@Test
	public void clientSideServerPrincipal() throws Exception {
		TlsServerConnector server = new TlsServerConnector(ConnectorTestUtil.serverContext, new InetSocketAddress(0),
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
		serverCatcher.blockUntilSize(1);

		msg = ConnectorTestUtil.createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 100, null);
		server.send(msg);
		clientCatcher.blockUntilSize(1);

		RawData receivedMessage = clientCatcher.getMessage(0);
		assertThat(receivedMessage, is(notNullValue()));
		assertThat(receivedMessage.getSenderIdentity(), is(ConnectorTestUtil.serverSubjectDN));
	}

	@Test
	public void clientSideDoesntTrustServer() throws Exception {
		/* client doesn't trust server. use different ca's for client side trust */
		SSLTestContext clientContext = ConnectorTestUtil.initializeNoTrustContext(ConnectorTestUtil.CLIENT_NAME, null);
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

		/*
		 * a client always checks the servers certificate, so the message never
		 * arrives
		 */
		assertThat(serverCatcher.hasMessage(0), is(false));
	}
}
