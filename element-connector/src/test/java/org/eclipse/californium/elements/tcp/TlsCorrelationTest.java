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
import org.eclipse.californium.elements.tcp.TlsServerConnector.ClientAuthMode;
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

	/**
	 * Test, if the correlation context is determined proper. Send a request and
	 * check, if the response has the same correlation context on the client
	 * side. Send a second request and check, if this has the same correlation
	 * context on the client side. Also check, if the server response is sent
	 * with the same context as the request was received.
	 */
	@Test
	public void testCorrelationContext() throws Exception {
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

		/* client context sent */
		CorrelationContext context = clientCallback.getCorrelationContext();
		assertThat("Cientside no sent TLS Correlation Context", context, is(instanceOf(TlsCorrelationContext.class)));
		TlsCorrelationContext clientContext = (TlsCorrelationContext) context;
		assertThat(clientContext.getSessionId(), is(not(isEmptyOrNullString())));
		assertThat(clientContext.getCipher(), is(not(isEmptyOrNullString())));

		/* server context received, matching client TLS context */
		context = serverCatcher.getMessage(0).getCorrelationContext();
		assertThat("Serverside no received TLS Correlation Context", context,
				is(instanceOf(TlsCorrelationContext.class)));
		TlsCorrelationContext serverContext = (TlsCorrelationContext) context;
		assertThat(serverContext.getSessionId(), is(clientContext.getSessionId()));
		assertThat(serverContext.getCipher(), is(clientContext.getCipher()));

		// Response message must go over the same connection client already
		// opened
		SimpleMessageCallback serverCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil
				.createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 10000, serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(1);

		/* server context sent, matching received context */
		context = serverCallback.getCorrelationContext();
		assertThat("Serverside no sent TLS Correlation Context", context, is(instanceOf(TlsCorrelationContext.class)));
		TlsCorrelationContext serverResponseContext = (TlsCorrelationContext) context;
		assertThat(serverResponseContext.getSessionId(), is(serverContext.getSessionId()));
		assertThat(serverResponseContext.getCipher(), is(serverContext.getCipher()));
		assertThat(serverResponseContext.getConnectionId(), is(serverContext.getConnectionId()));

		/* client context received, matching sent context */
		context = clientCatcher.getMessage(0).getCorrelationContext();
		assertThat("Clientside no received TLS Correlation Context", context,
				is(instanceOf(TlsCorrelationContext.class)));
		TlsCorrelationContext tlsContext = (TlsCorrelationContext) context;
		assertThat(tlsContext.getSessionId(), is(clientContext.getSessionId()));
		assertThat(tlsContext.getCipher(), is(clientContext.getCipher()));
		assertThat(tlsContext.getConnectionId(), is(clientContext.getConnectionId()));

		/* send second request */
		clientCallback = new SimpleMessageCallback();
		msg = ConnectorTestUtil.createMessage(server.getAddress(), 100, clientCallback);
		client.send(msg);

		/* client context second sent, matching first sent context */
		context = clientCallback.getCorrelationContext(ConnectorTestUtil.CONTEXT_TIMEOUT_IN_MS);
		assertTrue("no second request TLS Correlation Context", context instanceof TlsCorrelationContext);
		tlsContext = (TlsCorrelationContext) context;
		assertThat(tlsContext.getSessionId(), is(clientContext.getSessionId()));
		assertThat(tlsContext.getCipher(), is(clientContext.getCipher()));
		assertThat(tlsContext.getConnectionId(), is(clientContext.getConnectionId()));
	}

	/**
	 * Test, if the correlation context is different when reconnect after
	 * timeout. Send a request and fetch the correlation context on client and
	 * server side. Wait for connection timeout. Send a new request and fetch
	 * the correlation context on client and server side. The correlation
	 * contexts must be different.
	 */
	@Test
	public void testCorrelationContextWhenReconnectAfterTimeout() throws Exception {
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

		CorrelationContext serverContext = serverCatcher.getMessage(0).getCorrelationContext();
		CorrelationContext clientContext = clientCallback.getCorrelationContext();

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

		CorrelationContext serverContextAfterReconnect = serverCatcher.getMessage(1).getCorrelationContext();
		assertThat("Serverside no TLS Correlation Context after reconnect", serverContextAfterReconnect,
				is(instanceOf(TlsCorrelationContext.class)));
		// new (different) server side connection
		assertThat(serverContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(serverContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));
		// the session may be resumed ... so the session id may be not renewed
		assertThat(serverContextAfterReconnect, is(not(serverContext)));
	}

	/**
	 * Test, if the correlation context is different when reconnect after server
	 * stop/start. Send a request and fetch the correlation context on client
	 * and server side. Stop/start the server. Send a new request and fetch the
	 * correlation context on client and server side. The correlation contexts
	 * must be different.
	 */
	@Test
	public void testCorrelationContextWhenReconnectAfterStopStart() throws Exception {
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

		CorrelationContext serverContext = serverCatcher.getMessage(0).getCorrelationContext();
		CorrelationContext clientContext = clientCallback.getCorrelationContext();

		// restart server, should trigger a reconnect
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
		// the session may be resumed ... so the session id may be not renewed
		assertThat(clientContextAfterReconnect, is(not(clientContext)));

		CorrelationContext serverContextAfterReconnect = serverCatcher.getMessage(1).getCorrelationContext();
		assertThat("Serverside no TLS Correlation Context after reconnect", serverContextAfterReconnect,
				is(instanceOf(TlsCorrelationContext.class)));
		// new (different) server side connection
		assertThat(serverContextAfterReconnect.get(TcpCorrelationContext.KEY_CONNECTION_ID),
				is(not(serverContext.get(TcpCorrelationContext.KEY_CONNECTION_ID))));
		// the session may be resumed ... so the session id may be not renewed
		assertThat(serverContextAfterReconnect, is(not(serverContext)));
	}

	/**
	 * Test, if the clients principal is reported on receiving a message at
	 * server side.
	 */
	@Test
	public void testServerSideClientPrincipal() throws Exception {
		TlsServerConnector server = new TlsServerConnector(ConnectorTestUtil.serverContext, ClientAuthMode.NEEDED,
				new InetSocketAddress(0), ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
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

	/**
	 * Test, if the connection is refused (no message received), when the
	 * clients certificate is broken (private key doesn't match the public key
	 * in its certificate).
	 */
	@Test
	public void testServerSideClientWithBrokenCertificate() throws Exception {
		/*
		 * create client credential using the client certificate, but wrong
		 * private key.
		 */
		SSLTestContext clientContext = ConnectorTestUtil.initializeContext(ConnectorTestUtil.SERVER_NAME,
				ConnectorTestUtil.CLIENT_NAME, null);

		TlsServerConnector server = new TlsServerConnector(ConnectorTestUtil.serverContext, ClientAuthMode.NEEDED,
				new InetSocketAddress(0), ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
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

	/**
	 * Test, if the severs principal is reported on receiving a message at
	 * client side.
	 */
	@Test
	public void testClientSideServerPrincipal() throws Exception {
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

	/**
	 * Test, if the connection is refused (no message received), when the server
	 * certificate is broken (private key doesn't match the public key in its
	 * certificate).
	 */
	@Test
	public void testClientSideServerWithBrokenCertificate() throws Exception {
		/*
		 * create server credential using the server certificate, but wrong
		 * private key.
		 */
		SSLTestContext serverContext = ConnectorTestUtil.initializeContext(ConnectorTestUtil.CLIENT_NAME,
				ConnectorTestUtil.SERVER_NAME, null);

		TlsServerConnector server = new TlsServerConnector(serverContext.context, ClientAuthMode.NEEDED,
				new InetSocketAddress(0), ConnectorTestUtil.NUMBER_OF_THREADS, ConnectorTestUtil.IDLE_TIMEOUT_IN_S);
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
	}

}
