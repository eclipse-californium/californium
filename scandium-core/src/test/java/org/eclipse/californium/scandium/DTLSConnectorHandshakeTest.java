/*******************************************************************************
 * Copyright (c) 2018 - 2019 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial creation
 *                                                    Based on the original test
 *                                                    in DTLSConnectorTest.
 *                                                    Updated to use ConnectorHelper
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.eclipse.californium.scandium.ConnectorHelper.CLIENT_IDENTITY;
import static org.eclipse.californium.scandium.ConnectorHelper.CLIENT_IDENTITY_SECRET;
import static org.eclipse.californium.scandium.ConnectorHelper.MAX_TIME_TO_WAIT_SECS;
import static org.eclipse.californium.scandium.ConnectorHelper.SCOPED_CLIENT_IDENTITY;
import static org.eclipse.californium.scandium.ConnectorHelper.SCOPED_CLIENT_IDENTITY_SECRET;
import static org.eclipse.californium.scandium.ConnectorHelper.SERVERNAME;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.junit.Assert.assertThat;
import static org.junit.Assume.assumeTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.eclipse.californium.scandium.ConnectorHelper.LatchSessionListener;
import org.eclipse.californium.scandium.auth.ApplicationLevelInfoSupplier;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.ConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AsyncInMemoryPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@link DTLSConnector}.
 * <p>
 * Mainly contains integration test cases verifying the correct interaction
 * between a client and a server during handshakes with and without SNI.
 */
@Category(Medium.class)
public class DTLSConnectorHandshakeTest {

	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT,
			DtlsNetworkRule.Mode.NATIVE);

	@ClassRule
	public static ThreadsRule cleanup = new ThreadsRule();

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;
	private static final String DEVICE_ID = "the-device";
	private static final String KEY_DEVICE_ID = "device-id";
	private static final String KEY_SERVER_NAME = "server-name";

	private static AdditionalInfo additionalClientInfo;
	private static AdditionalInfo additionalServerInfo;

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	ConnectorHelper serverHelper;

	DTLSConnector client;
	InMemoryConnectionStore clientConnectionStore;
	ApplicationLevelInfoSupplier clientInfoSupplier;
	ApplicationLevelInfoSupplier serverInfoSupplier;
	AsyncInMemoryPskStore asyncPskStore;

	/**
	 * Initializes static variables.
	 */
	@BeforeClass
	public static void init() {

		Map<String, Object> info = new HashMap<>();
		info.put(KEY_SERVER_NAME, SERVERNAME);
		additionalServerInfo = AdditionalInfo.from(info);

		info.clear();
		info.put(KEY_DEVICE_ID, DEVICE_ID);
		additionalClientInfo = AdditionalInfo.from(info);
	}

	/**
	 * Sets up the fixture.
	 */
	@Before
	public void setUp() {

		serverInfoSupplier = mock(ApplicationLevelInfoSupplier.class);
		when(serverInfoSupplier.getInfo(any(Principal.class))).thenReturn(additionalServerInfo);
		clientInfoSupplier = mock(ApplicationLevelInfoSupplier.class);
		when(clientInfoSupplier.getInfo(any(Principal.class))).thenReturn(additionalClientInfo);
	}

	/**
	 * Destroys the server and client.
	 */
	@After
	public void cleanUp() {
		if (asyncPskStore != null) {
			asyncPskStore.shutdown();
			asyncPskStore = null;
		}
		if (serverHelper != null) {
			serverHelper.destroyServer();
		}
		if (client != null) {
			client.destroy();
		}
	}

	private void assertClientPrincipalHasAdditionalInfo(Principal clientIdentity) {
		ConnectorHelper.assertPrincipalHasAdditionalInfo(clientIdentity, KEY_DEVICE_ID, DEVICE_ID);
	}

	private void startServer(boolean enableSni, boolean clientAuthRequired, boolean clientAuthWanted, ConnectionIdGenerator cidGenerator)
			throws IOException, GeneralSecurityException {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setClientAuthenticationRequired(clientAuthRequired)
				.setClientAuthenticationWanted(clientAuthWanted)
				.setConnectionIdGenerator(cidGenerator)
				.setLoggingTag("server")
				.setSniEnabled(enableSni)
				.setApplicationLevelInfoSupplier(clientInfoSupplier);
		startServer(builder);
	}

	private void startServer(DtlsConnectorConfig.Builder builder)
			throws IOException, GeneralSecurityException {
		serverHelper = new ConnectorHelper();
		serverHelper.startServer(builder);
	}

	private void startClientPsk(boolean enableSni, String hostname, ConnectionIdGenerator cidGenerator, PskStore pskStore) throws Exception {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setPskStore(pskStore)
				.setConnectionIdGenerator(cidGenerator);
		startClient(enableSni, hostname, builder);
	}

	private void startClientRpk(boolean enableSni, String hostname) throws Exception {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRpkTrustAll()
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientPublicKey());
		startClient(enableSni, hostname, builder);
	}

	private void startAnonymClientRpk(boolean enableSni, String hostname) throws Exception {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRpkTrustAll();
		startClient(enableSni, hostname, builder);
	}

	private void startClientX509(boolean enableSni, String hostname) throws Exception {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setTrustStore(new Certificate[0])
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientCertificateChain());
		startClient(enableSni, hostname, builder);
	}

	private void startAnonymClientX509(boolean enableSni, String hostname) throws Exception {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setTrustStore(new Certificate[0]);
		startClient(enableSni, hostname, builder);
	}

	private void startClient(boolean enableSni, String hostname, DtlsConnectorConfig.Builder builder) throws Exception {
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		builder.setAddress(clientEndpoint)
				.setLoggingTag("client")
				.setReceiverThreadCount(1)
				.setConnectionThreadCount(1)
				.setSniEnabled(enableSni)
				.setClientOnly()
				.setMaxConnections(CLIENT_CONNECTION_STORE_CAPACITY)
				.setApplicationLevelInfoSupplier(serverInfoSupplier);
		DtlsConnectorConfig clientConfig = builder.build();

		client = serverHelper.createClient(clientConfig);
		RawData raw = RawData.outbound("Hello World".getBytes(),
				new AddressEndpointContext(serverHelper.serverEndpoint, hostname, null), null, false);
		serverHelper.givenAnEstablishedSession(client, raw, true);
		final DTLSSession session = client.getSessionByAddress(serverHelper.serverEndpoint);
		assertThat(session, is(notNullValue()));
		ConnectorHelper.assertPrincipalHasAdditionalInfo(session.getPeerIdentity(), KEY_SERVER_NAME, ConnectorHelper.SERVERNAME);
	}

	private void startClientFailing(DtlsConnectorConfig.Builder builder, EndpointContext destination) throws Exception {
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		builder.setAddress(clientEndpoint)
				.setLoggingTag("client")
				.setReceiverThreadCount(1)
				.setConnectionThreadCount(1)
				.setClientOnly()
				.setMaxConnections(CLIENT_CONNECTION_STORE_CAPACITY);
		DtlsConnectorConfig clientConfig = builder.build();

		client = serverHelper.createClient(clientConfig);
		client.start();
		SimpleMessageCallback callback = new SimpleMessageCallback();
		RawData raw = RawData.outbound("Hello World".getBytes(), destination, callback, false);
		client.send(raw);
		Throwable error = callback.getError(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS));
		assertThat("client side error missing", error, is(notNullValue()));
	}

	@Test
	public void testPskHandshakeClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false, null);
		startClientPsk(false, null, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeClientWithoutSniAndServerWithSni() throws Exception {
		startServer(true, true, false, null);
		startClientPsk(false, null, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(":" + CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false, null);
		startClientPsk(false, SERVERNAME, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithServernameClientWithoutSniAndServerWithSni() throws Exception {
		startServer(true, true, false, null);
		startClientPsk(false, SERVERNAME, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(":" + CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeClientWithSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false, null);
		startClientPsk(true, null, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeClientWithSniAndServerWithSni() throws Exception {
		startServer(true, true, false, null);
		startClientPsk(true, null, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(":" + CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithServernameClientWithSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false, null);
		startClientPsk(true, SERVERNAME, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithServernameClientWithSniAndServerWithSni() throws Exception {
		startServer(true, true, false, null);
		startClientPsk(true, SERVERNAME, null, new StaticPskStore(SCOPED_CLIENT_IDENTITY, SCOPED_CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(SERVERNAME + ":" + SCOPED_CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testRpkHandshakeClientWithSniAndServerWithSni() throws Exception {
		startServer(true, true, false, null);
		startClientRpk(true, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), startsWith("ni:///sha-256;"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testRpkHandshakeClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false, null);
		startClientRpk(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), startsWith("ni:///sha-256;"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testRpkHandshakeWithServernameClientWithSniAndServerWithSni() throws Exception {
		startServer(true, true, false, null);
		startClientRpk(true, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), startsWith("ni:///sha-256;"));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testRpkHandshakeWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false, null);
		startClientRpk(false, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), startsWith("ni:///sha-256;"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testX509HandshakeClientWithSniAndServerWithSni() throws Exception {
		startServer(true, true, false, null);
		startClientX509(true, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testX509HandshakeClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false, null);
		startClientX509(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testX509HandshakeWithServernameClientWithSniAndServerWithSni() throws Exception {
		startServer(true, true, false, null);
		startClientX509(true, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client"));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testX509HandshakeWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false, null);
		startClientX509(false, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testRpkHandshakeNoneAuthClientWithSniAndServerWithSni() throws Exception {
		startServer(true, false, false, null);
		startClientRpk(true, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class));
	}

	@Test
	public void testRpkHandshakeNoneAuthClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, false, false, null);
		startClientRpk(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class));
	}

	@Test
	public void testRpkHandshakeNoneAuthWithServernameClientWithSniAndServerWithSni() throws Exception {
		startServer(true, false, false, null);
		startClientRpk(true, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class));
	}

	@Test
	public void testRpkHandshakeNoneAuthWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, false, false, null);
		startClientRpk(false, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class));
	}

	@Test
	public void testX509HandshakeNoneAuthClientWithSniAndServerWithSni() throws Exception {
		startServer(true, false, false, null);
		startClientX509(true, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class));
	}

	@Test
	public void testX509HandshakeNoneAuthClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, false, false, null);
		startClientX509(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class));
	}

	@Test
	public void testX509HandshakeNoneAuthWithServernameClientWithSniAndServerWithSni() throws Exception {
		startServer(true, false, false, null);
		startClientX509(true, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class));
	}

	@Test
	public void testX509HandshakeNoneAuthWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, false, false, null);
		startClientX509(false, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class));
	}

	@Test
	public void testRpkHandshakeAuthWanted() throws Exception {
		startServer(false, false, true, null);
		startClientRpk(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testRpkHandshakeAuthWantedAnonymClient() throws Exception {
		startServer(false, false, true, null);
		startAnonymClientRpk(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class));
	}

	@Test
	public void testX509HandshakeAuthWanted() throws Exception {
		startServer(false, false, true, null);
		startClientX509(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testX509HandshakeAuthWantedAnonymClient() throws Exception {
		startServer(false, false, true, null);
		startAnonymClientX509(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class));
	}

	@Test
	public void testX509MixedCertificateChainHandshakeAuthWantedAnonymClient() throws Exception {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setClientAuthenticationWanted(true)
				.setIdentity(DtlsTestTools.getServerRsPrivateKey(), DtlsTestTools.getServerRsaCertificateChain())
				.setApplicationLevelInfoSupplier(clientInfoSupplier);
		startServer(builder);
		startAnonymClientX509(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class));
	}

	@Test
	public void testPskHandshakeWithCid() throws Exception {
		startServer(false, false, false, new SingleNodeConnectionIdGenerator(6));
		startClientPsk(false, null, new SingleNodeConnectionIdGenerator(4), new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithServerCid() throws Exception {
		startServer(false, false, false, new SingleNodeConnectionIdGenerator(6));
		startClientPsk(false, null, new SingleNodeConnectionIdGenerator(0), new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithClientCid() throws Exception {
		startServer(false, false, false, new SingleNodeConnectionIdGenerator(0));
		startClientPsk(false, null, new SingleNodeConnectionIdGenerator(4), new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithoutServerCid() throws Exception {
		startServer(false, false, false, null);
		startClientPsk(false, null, new SingleNodeConnectionIdGenerator(4), new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithoutClientCid() throws Exception {
		startServer(false, false, false, new SingleNodeConnectionIdGenerator(0));
		startClientPsk(false, null, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithoutSession() throws Exception {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setClientAuthenticationRequired(false)
				.setClientAuthenticationWanted(false)
				.setSniEnabled(false)
				.setNoServerSessionId(true)
				.setApplicationLevelInfoSupplier(clientInfoSupplier);
		startServer(builder);
		startClientPsk(false, null, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeSyncPskSecret() throws Exception {
		PskStore pskStore = new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
		asyncPskStore = new AsyncInMemoryPskStore(pskStore).setDelay(0).setSecretMode(false);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setClientAuthenticationRequired(false)
				.setClientAuthenticationWanted(false)
				.setSniEnabled(false)
				.setNoServerSessionId(true)
				.setApplicationLevelInfoSupplier(clientInfoSupplier)
				.setAdvancedPskStore(asyncPskStore);
		startServer(builder);
		startClientPsk(false, null, null, pskStore);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeSyncMasterSecret() throws Exception {
		PskStore pskStore = new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
		asyncPskStore = new AsyncInMemoryPskStore(pskStore).setDelay(0).setSecretMode(true);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setClientAuthenticationRequired(false)
				.setClientAuthenticationWanted(false)
				.setSniEnabled(false)
				.setNoServerSessionId(true)
				.setApplicationLevelInfoSupplier(clientInfoSupplier)
				.setAdvancedPskStore(asyncPskStore);
		startServer(builder);
		startClientPsk(false, null, null, pskStore);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeAsyncPskSecret() throws Exception {
		PskStore pskStore = new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
		asyncPskStore = new AsyncInMemoryPskStore(pskStore).setDelay(1).setSecretMode(false);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setClientAuthenticationRequired(false)
				.setClientAuthenticationWanted(false)
				.setSniEnabled(false)
				.setNoServerSessionId(true)
				.setApplicationLevelInfoSupplier(clientInfoSupplier)
				.setAdvancedPskStore(asyncPskStore);
		startServer(builder);
		startClientPsk(false, null, null, pskStore);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeAsyncMasterSecret() throws Exception {
		PskStore pskStore = new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
		asyncPskStore = new AsyncInMemoryPskStore(pskStore).setDelay(1).setSecretMode(true);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setClientAuthenticationRequired(false)
				.setClientAuthenticationWanted(false)
				.setSniEnabled(false)
				.setNoServerSessionId(true)
				.setApplicationLevelInfoSupplier(clientInfoSupplier)
				.setAdvancedPskStore(asyncPskStore);
		startServer(builder);
		startClientPsk(false, null, null, pskStore);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testEcdhPskHandshake() throws Exception {
		startServer(false, false,  false,  null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRecommendedCipherSuitesOnly(false)
				.setPskStore(new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()))
				.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256));
	}

	@Test
	public void testPskCbcHandshake() throws Exception {
		startServer(false, false,  false,  null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setPskStore(new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()))
				.setRecommendedCipherSuitesOnly(false)
				.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256));
	}

	@Test
	public void testPskCcm8Handshake() throws Exception {
		startServer(false, false,  false,  null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setPskStore(new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()))
				.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8));
	}

	@Test
	public void testPsk256Ccm8Handshake() throws Exception {
		assumeTrue("AES256 requires JVM support!", CipherSuite.TLS_PSK_WITH_AES_256_CCM_8.isSupported());
		startServer(false, false,  false,  null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setPskStore(new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()))
				.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_256_CCM_8);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_256_CCM_8));
	}

	@Test
	public void testPskCcmHandshake() throws Exception {
		startServer(false, false,  false,  null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setPskStore(new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()))
				.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_128_CCM));
	}

	@Test
	public void testPsk256CcmHandshake() throws Exception {
		assumeTrue("AES256 requires JVM support!", CipherSuite.TLS_PSK_WITH_AES_256_CCM.isSupported());
		startServer(false, false,  false,  null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setPskStore(new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()))
				.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_256_CCM);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_256_CCM));
	}

	@Test
	public void testPskGcmHandshake() throws Exception {
		assumeTrue("GCM requires JVM support!", CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256.isSupported());
		startServer(false, false,  false,  null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setPskStore(new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()))
				.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256));
	}

	@Test
	public void testRpkCbcHandshake() throws Exception {
		startServer(false, false, false, null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRpkTrustAll()
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientPublicKey())
				.setRecommendedCipherSuitesOnly(false)
				.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256));
	}

	@Test
	public void testRpkCcm8Handshake() throws Exception {
		startServer(false, false, false, null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRpkTrustAll()
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientPublicKey())
				.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
	}

	@Test
	public void testRpk256Ccm8Handshake() throws Exception {
		assumeTrue("AES256 requires JVM support!", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8.isSupported());
		startServer(false, false, false, null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRpkTrustAll()
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientPublicKey())
				.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8));
	}

	@Test
	public void testRpkCcmHandshake() throws Exception {
		startServer(false, false, false, null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRpkTrustAll()
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientPublicKey())
				.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM));
	}

	@Test
	public void testRpk256CcmHandshake() throws Exception {
		assumeTrue("AES256 requires JVM support!", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM.isSupported());
		startServer(false, false, false, null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRpkTrustAll()
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientPublicKey())
				.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM));
	}

	@Test
	public void testRpk256CbcHandshake() throws Exception {
		assumeTrue("AES256 requires JVM support!", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.isSupported());
		startServer(false, false, false, null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRpkTrustAll()
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientPublicKey())
				.setRecommendedCipherSuitesOnly(false)
				.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA));
	}

	@Test
	public void testRpk256Cbc384Handshake() throws Exception {
		assumeTrue("AES256 requires JVM support!", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384.isSupported());
		startServer(false, false, false, null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRpkTrustAll()
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientPublicKey())
				.setRecommendedCipherSuitesOnly(false)
				.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384));
	}

	@Test
	public void testRpkGcmHandshake() throws Exception {
		assumeTrue("GCM requires JVM support!", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.isSupported());
		startServer(false, false, false, null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setRpkTrustAll()
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientPublicKey())
				.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
		startClient(false,  null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256));
	}

	@Test
	public void testX509HandshakeSignatureAlgorithmsExtensionSha256Ecdsa() throws Exception {
		startServer(false, true, false, null);

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setTrustStore(new Certificate[0])
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientCertificateChain())
				.setSupportedSignatureAlgorithms(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
				.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

		startClient(false, null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
		assertThat(serverHelper.establishedServerSession.getSignatureAndHashAlgorithm(), is(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA));
	}

	@Test
	public void testX509HandshakeSignatureAlgorithmsExtensionSha384Ecdsa() throws Exception {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setClientAuthenticationRequired(true)
				.setSupportedSignatureAlgorithms(SignatureAndHashAlgorithm.SHA384_WITH_ECDSA,
						SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
				.setApplicationLevelInfoSupplier(clientInfoSupplier);
		startServer(builder);

		builder = new DtlsConnectorConfig.Builder()
				.setTrustStore(new Certificate[0])
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientCertificateChain())
				.setSupportedSignatureAlgorithms(SignatureAndHashAlgorithm.SHA384_WITH_ECDSA,
						SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
				.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

		startClient(false, null, builder);
		assertThat(serverHelper.establishedServerSession.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
		assertThat(serverHelper.establishedServerSession.getSignatureAndHashAlgorithm(), is(SignatureAndHashAlgorithm.SHA384_WITH_ECDSA));
	}

	@Test
	public void testX509HandshakeFailingWrongClientCertificate() throws Exception {
		startServer(false, true, false, null);

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setTrustStore(new Certificate[0])
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getServerCertificateChain());

		startClientFailing(builder, new AddressEndpointContext(serverHelper.serverEndpoint));

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));
		assertThat(cause.getMessage(), containsString("CertificateVerify message could not be verified."));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));
		assertThat(cause.getMessage(), containsString("fatal alert"));
	}

	@Test
	public void testX509HandshakeFailingMissingClientCertificate() throws Exception {
		startServer(false, true, false, null);

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setTrustStore(new Certificate[0]);

		startClientFailing(builder, new AddressEndpointContext(serverHelper.serverEndpoint));

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));
		assertThat(cause.getMessage(), containsString("Client Certificate required!"));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));
		assertThat(cause.getMessage(), containsString("fatal alert"));
	}

	@Test
	public void testX509HandshakeFailingNoCommonCurve() throws Exception {
		startServer(false, false, false, null);

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setTrustStore(new Certificate[0])
				.setRecommendedSupportedGroupsOnly(false)
				.setSupportedGroups("secp521r1");

		startClientFailing(builder, new AddressEndpointContext(serverHelper.serverEndpoint));

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));
		assertThat(cause.getMessage(), containsString("Client proposed unsupported cipher suites only"));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));
		assertThat(cause.getMessage(), containsString("fatal alert"));
	}

	@Test
	public void testServerDropsX509Principal() throws Exception {
		startServer(false, true, false, null);
		startClientX509(false, null);
		startClientPsk(false,  null,  null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		int remainingCapacity = serverHelper.serverConnectionStore.remainingCapacity();
		Future<Void> future = serverHelper.server.startDropConnectionsForPrincipal(principal);
		future.get();
		assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remainingCapacity + 1));
	}

	@Test
	public void testServerDropsPreSharedKeyPrincipal() throws Exception {
		startServer(false, false, false, null);
		startClientX509(false, null);
		startClientPsk(false,  null,  null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		startClientPsk(false,  null,  null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		int remainingCapacity = serverHelper.serverConnectionStore.remainingCapacity();
		Future<Void> future = serverHelper.server.startDropConnectionsForPrincipal(principal);
		future.get();
		assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remainingCapacity + 2));
	}

	@Test
	public void testDefaultHandshakeModeNone() throws Exception {
		startServer(false, false, true, null);

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setDefaultHandshakeMode(DtlsEndpointContext.HANDSHAKE_MODE_NONE)
				.setRpkTrustAll()
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientPublicKey());

		EndpointContext endpointContext = new AddressEndpointContext(serverHelper.serverEndpoint);
		startClientFailing(builder, endpointContext);

		SimpleMessageCallback callback = new SimpleMessageCallback();
		RawData raw = RawData.outbound(
				"Hello World, 2!".getBytes(), MapBasedEndpointContext.addEntries(endpointContext,
						DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_AUTO),
				callback, false);
		client.send(raw);

		endpointContext = callback.getEndpointContext(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS));
		assertThat("client failed to send data", endpointContext, is(notNullValue()));
	}

	@Test
	public void testDefaultHandshakeModeAuto() throws Exception {
		startServer(false, false, true, null);

		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setDefaultHandshakeMode(DtlsEndpointContext.HANDSHAKE_MODE_AUTO)
				.setRpkTrustAll()
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientPublicKey());

		EndpointContext endpointContext = new AddressEndpointContext(serverHelper.serverEndpoint);
		startClientFailing(builder, MapBasedEndpointContext.addEntries(endpointContext,
				DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_NONE));

		SimpleMessageCallback callback = new SimpleMessageCallback();
		RawData raw = RawData.outbound("Hello World, 2!".getBytes(), endpointContext, callback, false);
		client.send(raw);
	
		endpointContext = callback.getEndpointContext(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS));
		assertThat("client failed to send data", endpointContext, is(notNullValue()));
	}

}
