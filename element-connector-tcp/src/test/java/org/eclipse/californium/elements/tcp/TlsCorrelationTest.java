/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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

import static org.eclipse.californium.elements.tcp.ConnectorTestUtil.*;
import static org.eclipse.californium.elements.tcp.TlsConnectorTestUtil.*;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.text.IsEmptyString.isEmptyOrNullString;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.TcpEndpointContext;
import org.eclipse.californium.elements.TlsEndpointContext;
import org.eclipse.californium.elements.TlsEndpointContextMatcher;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.tcp.TlsConnectorTestUtil.SSLTestContext;
import org.eclipse.californium.elements.tcp.TlsServerConnector.ClientAuthMode;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.hamcrest.CoreMatchers;
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
		TlsConnectorTestUtil.initializeSsl();
	}

	@After
	public void cleanup() {
		for (Connector connector : cleanup) {
			connector.stop();
		}
	}

	/**
	 * Test, if the correlation context is determined proper.
	 *
	 * <pre>
	 * 1. Send a request and check, if the client created a secure correlation context.
	 * 2. Check, if the server received the request within the same security information
	 *    in the correlation context as the client
	 * 3. Send a response and check, if the server sent it with same correlation context
	 *    as the request was received.
	 * 4. Check, if the client received the response within the same correlation context
	 *    as the request was sent.
	 * 5. Send a second request and check, if this has the same correlation
	 *    context on the client side as the first.
	 * </pre>
	 */
	@Test
	public void testCorrelationContext() throws Exception {
		TlsServerConnector server = new TlsServerConnector(serverSslContext, createServerAddress(0), NUMBER_OF_THREADS,
				IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(clientSslContext, NUMBER_OF_THREADS,
				CONNECTION_TIMEOUT_IN_MS, IDLE_TIMEOUT_IN_S);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);

		/* client context sent */
		EndpointContext clientContext = clientCallback.getEndpointContext();
		assertThat(clientContext.get(TcpEndpointContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));
		assertThat(clientContext.get(TlsEndpointContext.KEY_SESSION_ID), is(not(isEmptyOrNullString())));
		assertThat(clientContext.get(TlsEndpointContext.KEY_CIPHER), is(not(isEmptyOrNullString())));

		/* server context received, matching client TLS context */
		EndpointContext serverContext = serverCatcher.getEndpointContext(0);
		assertThat(serverContext.get(TcpEndpointContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));
		assertThat(serverContext.get(TlsEndpointContext.KEY_SESSION_ID), is(clientContext.get(TlsEndpointContext.KEY_SESSION_ID)));
		assertThat(serverContext.get(TlsEndpointContext.KEY_CIPHER), is(clientContext.get(TlsEndpointContext.KEY_CIPHER)));

		// Response message must go over the same connection the client already
		// opened
		SimpleMessageCallback serverCallback = new SimpleMessageCallback();
		msg = createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 10000, serverCallback);
		server.send(msg);
		clientCatcher.blockUntilSize(1);

		/* server context sent, matching received context */
		EndpointContext serverResponseContext = serverCallback.getEndpointContext();
		assertThat(serverResponseContext.get(TlsEndpointContext.KEY_SESSION_ID), is(serverContext.get(TlsEndpointContext.KEY_SESSION_ID)));
		assertThat(serverResponseContext.get(TlsEndpointContext.KEY_CIPHER), is(serverContext.get(TlsEndpointContext.KEY_CIPHER)));
		assertThat(serverResponseContext.get(TcpEndpointContext.KEY_CONNECTION_ID), is(serverContext.get(TcpEndpointContext.KEY_CONNECTION_ID)));

		/* client context received, matching sent context */
		EndpointContext tlsContext = clientCatcher.getEndpointContext(0);
		assertThat(tlsContext.get(TlsEndpointContext.KEY_SESSION_ID), is(clientContext.get(TlsEndpointContext.KEY_SESSION_ID)));
		assertThat(tlsContext.get(TlsEndpointContext.KEY_CIPHER), is(clientContext.get(TlsEndpointContext.KEY_CIPHER)));
		assertThat(tlsContext.get(TcpEndpointContext.KEY_CONNECTION_ID), is(clientContext.get(TcpEndpointContext.KEY_CONNECTION_ID)));

		/* send second request */
		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, clientCallback);
		client.send(msg);

		/* client context second sent, matching first sent context */
		tlsContext = clientCallback.getEndpointContext(CONTEXT_TIMEOUT_IN_MS);
		assertThat(tlsContext.get(TlsEndpointContext.KEY_SESSION_ID), is(clientContext.get(TlsEndpointContext.KEY_SESSION_ID)));
		assertThat(tlsContext.get(TlsEndpointContext.KEY_CIPHER), is(clientContext.get(TlsEndpointContext.KEY_CIPHER)));
		assertThat(tlsContext.get(TcpEndpointContext.KEY_CONNECTION_ID), is(clientContext.get(TcpEndpointContext.KEY_CONNECTION_ID)));
	}

	/**
	 * Test, if the correlation context is different when reconnect after
	 * timeout.
	 *
	 * <pre>
	 * 1. Send a request and fetch the correlation context on client and
	 *    server side.
	 * 2. Wait for connection timeout.
	 * 3. Send a new request and fetch the correlation context on client and
	 *    server side. The correlation contexts must be different.
	 * </pre>
	 */
	@Test
	public void testCorrelationContextWhenReconnectAfterTimeout() throws Exception {
		TlsServerConnector server = new TlsServerConnector(serverSslContext, createServerAddress(0), NUMBER_OF_THREADS,
				IDLE_TIMEOUT_RECONNECT_IN_S);
		TlsClientConnector client = new TlsClientConnector(clientSslContext, NUMBER_OF_THREADS,
				CONNECTION_TIMEOUT_IN_MS, IDLE_TIMEOUT_RECONNECT_IN_S);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);

		EndpointContext serverContext = serverCatcher.getEndpointContext(0);
		EndpointContext clientContext = clientCallback.getEndpointContext();

		// timeout connection, hopefully this triggers a reconnect
		Thread.sleep(TimeUnit.MILLISECONDS.convert(IDLE_TIMEOUT_RECONNECT_IN_S * 2, TimeUnit.SECONDS));

		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(2);

		EndpointContext clientContextAfterReconnect = clientCallback.getEndpointContext();
		// new (different) client side connection
		assertThat(clientContextAfterReconnect.get(TcpEndpointContext.KEY_CONNECTION_ID), is(not(clientContext.get(TcpEndpointContext.KEY_CONNECTION_ID))));
		// the session may be resumed ... so the session id may be not renewed
		assertThat(clientContextAfterReconnect, is(not(clientContext)));

		EndpointContext serverContextAfterReconnect = serverCatcher.getEndpointContext(1);
		// new (different) server side connection
		assertThat(serverContextAfterReconnect.get(TcpEndpointContext.KEY_CONNECTION_ID), is(not(serverContext.get(TcpEndpointContext.KEY_CONNECTION_ID))));
		// the session may be resumed ... so the session id may be not renewed
		assertThat(serverContextAfterReconnect, is(not(serverContext)));
	}

	/**
	 * Test, if the correlation context is different when reconnect after server
	 * stop/start.
	 *
	 * <pre>
	 * 1. Send a request and fetch the correlation context on client and
	 *    server side.
	 * 2. Stop/start the server.
	 * 3. Send a new request and fetch the correlation context on client and
	 *    server side. The correlation contexts must be different.
	 * </pre>
	 */
	@Test
	public void testCorrelationContextWhenReconnectAfterStopStart() throws Exception {
		TlsServerConnector server = new TlsServerConnector(serverSslContext, createServerAddress(0), NUMBER_OF_THREADS,
				IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(clientSslContext, NUMBER_OF_THREADS,
				CONNECTION_TIMEOUT_IN_MS, IDLE_TIMEOUT_IN_S);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);

		EndpointContext serverContext = serverCatcher.getEndpointContext(0);
		EndpointContext clientContext = clientCallback.getEndpointContext();

		// restart server, should trigger a reconnect
		server.stop();
		server.start();

		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(2);

		EndpointContext clientContextAfterReconnect = clientCallback.getEndpointContext();
		// new (different) client side connection
		assertThat(clientContextAfterReconnect.get(TcpEndpointContext.KEY_CONNECTION_ID), is(not(clientContext.get(TcpEndpointContext.KEY_CONNECTION_ID))));
		// the session may be resumed ... so the session id may be not renewed
		assertThat(clientContextAfterReconnect, is(not(clientContext)));

		EndpointContext serverContextAfterReconnect = serverCatcher.getEndpointContext(1);
		// new (different) server side connection
		assertThat(serverContextAfterReconnect.get(TcpEndpointContext.KEY_CONNECTION_ID), is(not(serverContext.get(TcpEndpointContext.KEY_CONNECTION_ID))));
		// the session may be resumed ... so the session id may be not renewed
		assertThat(serverContextAfterReconnect, is(not(serverContext)));
	}

	/**
	 * Test, if the correlation context provided for sending is handled proper
	 * on the client side.
	 * 
	 * <pre>
	 * 1. Send a request with correlation context and check, that the message
	 *    is dropped (server doesn't receive a message).
	 * 2. Send a request without correlation context and check, that the
	 *    message is sent (server receives the message).
	 * 3. Send a 2. request with retrieved correlation context and check,
	 *    that the message is sent (server receives a 2. message).
	 * 4. Send a 3. request with different correlation context and check,
	 *    that the message is dropped (server doesn't receive a 3. message).
	 * 5. Send a 4. request without correlation context and check, that the
	 *    message is sent (server receives a 3. message).
	 * </pre>
	 */
	@Test
	public void testClientSendingCorrelationContext() throws Exception {
		TlsEndpointContextMatcher matcher = new TlsEndpointContextMatcher();
		TlsServerConnector server = new TlsServerConnector(serverSslContext, createServerAddress(0), NUMBER_OF_THREADS,
				IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(clientSslContext, NUMBER_OF_THREADS,
				CONNECTION_TIMEOUT_IN_MS, IDLE_TIMEOUT_IN_S);

		client.setEndpointContextMatcher(matcher);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		EndpointContext invalidContext = new TlsEndpointContext(server.getAddress(), null, "n.a.", "n.a.", "n.a.");

		// message context without connector context => drop
		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = createMessage(100, invalidContext, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1, 2000);
		assertThat("Serverside received unexpected message", !serverCatcher.hasMessage(0));

		// no message context without connector context => send
		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, clientCallback);
		client.send(msg);
		serverCatcher.blockUntilSize(1);

		EndpointContext clientContext = clientCallback.getEndpointContext();
		assertThat(clientContext.get(TcpEndpointContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));
		assertThat(clientContext.get(TlsEndpointContext.KEY_SESSION_ID), is(not(isEmptyOrNullString())));
		assertThat(clientContext.get(TlsEndpointContext.KEY_CIPHER), is(not(isEmptyOrNullString())));

		// message context with matching connector context => send
		clientCallback = new SimpleMessageCallback();
		msg = createMessage(100, clientContext, clientCallback);
		client.send(msg);
		serverCatcher.blockUntilSize(2);

		// invalid message context with connector context => drop
		clientCallback = new SimpleMessageCallback();
		msg = createMessage(100, invalidContext, clientCallback);
		client.send(msg);

		serverCatcher.blockUntilSize(3, 2000);
		assertThat("Serverside received unexpected message", !serverCatcher.hasMessage(3));

		// no message context with connector context => send
		clientCallback = new SimpleMessageCallback();
		msg = createMessage(server.getAddress(), 100, clientCallback);
		client.send(msg);
		serverCatcher.blockUntilSize(3);
	}

	/**
	 * Test, if the correlation context provided for sending is handled proper
	 * on the server side.
	 *
	 * <pre>
	 * 1. Send a request without correlation context and check, that the
	 *    message is received by the server.
	 * 2. Send a response with the received correlation context, and check,
	 *    if the client receives the response.
	 * 3. Send a 2. response without a correlation context, and check,
	 *    if the client received the 2. response.
	 * 4. Send a 3. response with a different correlation context, and check,
	 *    if the client doesn't receive the 3. response.
	 * </pre>
	 */
	@Test
	public void testServerSendingCorrelationContext() throws Exception {
		TlsEndpointContextMatcher matcher = new TlsEndpointContextMatcher();
		TlsServerConnector server = new TlsServerConnector(serverSslContext, createServerAddress(0), NUMBER_OF_THREADS,
				IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(clientSslContext, NUMBER_OF_THREADS,
				CONNECTION_TIMEOUT_IN_MS, IDLE_TIMEOUT_IN_S);

		server.setEndpointContextMatcher(matcher);

		cleanup.add(server);
		cleanup.add(client);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		server.start();
		client.start();

		SimpleMessageCallback clientCallback = new SimpleMessageCallback();
		RawData msg = createMessage(server.getAddress(), 100, clientCallback);

		client.send(msg);
		serverCatcher.blockUntilSize(1);

		RawData receivedMsg = serverCatcher.getMessage(0);
		EndpointContext serverContext = serverCatcher.getEndpointContext(0);
		assertThat(serverContext.get(TcpEndpointContext.KEY_CONNECTION_ID), is(not(isEmptyOrNullString())));
		assertThat(serverContext.get(TlsEndpointContext.KEY_SESSION_ID), is(not(isEmptyOrNullString())));
		assertThat(serverContext.get(TlsEndpointContext.KEY_CIPHER), is(not(isEmptyOrNullString())));

		SimpleMessageCallback serverCallback = new SimpleMessageCallback();
		msg = createMessage(100, serverContext, serverCallback);
		server.send(msg);

		clientCatcher.blockUntilSize(1);

		serverCallback = new SimpleMessageCallback();
		msg = createMessage(receivedMsg.getInetSocketAddress(), 100, serverCallback);
		server.send(msg);

		clientCatcher.blockUntilSize(2);

		serverCallback = new SimpleMessageCallback();
		EndpointContext invalidContext = new TlsEndpointContext(receivedMsg.getInetSocketAddress(), null, "n.a.", "n.a.", "n.a.");
		msg = createMessage(100, invalidContext, serverCallback);
		server.send(msg);

		clientCatcher.blockUntilSize(3, 2000);
		assertThat("Clientside received unexpected message", !clientCatcher.hasMessage(3));
	}

	/**
	 * Test, if the clients principal is reported on receiving a message at
	 * server side.
	 */
	@Test
	public void testServerSideClientPrincipal() throws Exception {
		TlsServerConnector server = new TlsServerConnector(serverSslContext, ClientAuthMode.NEEDED,
				createServerAddress(0), NUMBER_OF_THREADS, IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(clientSslContext, NUMBER_OF_THREADS,
				CONNECTION_TIMEOUT_IN_MS, IDLE_TIMEOUT_IN_S);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		RawData msg = createMessage(server.getAddress(), 100, null);

		client.send(msg);
		serverCatcher.blockUntilSize(1);
		RawData receivedMessage = serverCatcher.getMessage(0);
		assertThat(receivedMessage, is(notNullValue()));

		assertThat(receivedMessage.getSenderIdentity(), is(CoreMatchers.<Principal>instanceOf(X509CertPath.class)));
		X509CertPath senderCertPath = (X509CertPath)receivedMessage.getSenderIdentity();
		assertThat(senderCertPath.getName(), is(clientCertPath.getName()));
		assertThat(senderCertPath.getPath(), is(clientCertPath.getPath()));
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
		SSLTestContext clientContext = initializeContext(SERVER_NAME, CLIENT_NAME, null);

		TlsServerConnector server = new TlsServerConnector(serverSslContext, ClientAuthMode.NEEDED,
				createServerAddress(0), NUMBER_OF_THREADS, IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(clientContext.context, NUMBER_OF_THREADS,
				CONNECTION_TIMEOUT_IN_MS, IDLE_TIMEOUT_IN_S);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		RawData msg = createMessage(server.getAddress(), 100, null);

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
		TlsServerConnector server = new TlsServerConnector(serverSslContext, createServerAddress(0), NUMBER_OF_THREADS,
				IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(clientSslContext, NUMBER_OF_THREADS,
				CONNECTION_TIMEOUT_IN_MS, IDLE_TIMEOUT_IN_S);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		RawData msg = createMessage(server.getAddress(), 100, null);

		client.send(msg);
		serverCatcher.blockUntilSize(1);

		msg = createMessage(serverCatcher.getMessage(0).getInetSocketAddress(), 100, null);
		server.send(msg);
		clientCatcher.blockUntilSize(1);

		RawData receivedMessage = clientCatcher.getMessage(0);
		assertThat(receivedMessage, is(notNullValue()));

		assertThat(receivedMessage.getSenderIdentity(), is(CoreMatchers.<Principal>instanceOf(X509CertPath.class)));
		X509CertPath senderCertPath = (X509CertPath)receivedMessage.getSenderIdentity();
		assertThat(senderCertPath.getName(), is(serverCertPath.getName()));
		assertThat(senderCertPath.getPath(), is(serverCertPath.getPath()));
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
		SSLTestContext serverContext = initializeContext(CLIENT_NAME, SERVER_NAME, null);

		TlsServerConnector server = new TlsServerConnector(serverContext.context, ClientAuthMode.NEEDED,
				createServerAddress(0), NUMBER_OF_THREADS, IDLE_TIMEOUT_IN_S);
		TlsClientConnector client = new TlsClientConnector(clientSslContext, NUMBER_OF_THREADS,
				CONNECTION_TIMEOUT_IN_MS, IDLE_TIMEOUT_IN_S);

		Catcher serverCatcher = new Catcher();
		Catcher clientCatcher = new Catcher();
		server.setRawDataReceiver(serverCatcher);
		client.setRawDataReceiver(clientCatcher);
		cleanup.add(server);
		cleanup.add(client);
		server.start();
		client.start();

		RawData msg = createMessage(server.getAddress(), 100, null);

		client.send(msg);
		serverCatcher.blockUntilSize(1, 2000);
		assertThat(serverCatcher.hasMessage(0), is(false));
	}

}
