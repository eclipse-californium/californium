/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial creation
 *                                                    Based on the original test
 *                                                    in DTLSConnectorTest.
 *                                                    Updated to use ConnectorHelper
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.eclipse.californium.scandium.ConnectorHelper.*;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.cert.Certificate;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.scandium.category.Medium;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.pskstore.PskStore;
import org.eclipse.californium.scandium.dtls.pskstore.StaticPskStore;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.junit.After;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies behavior of {@link DTLSConnector}.
 * <p>
 * Mainly contains integration test cases verifying the correct interaction
 * between a client and a server during handshakes with and without SNI.
 */
@Category(Medium.class)
public class DTLSConnectorHandshakeTest {

	public static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnectorHandshakeTest.class.getName());

	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT,
			DtlsNetworkRule.Mode.NATIVE);

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;

	ConnectorHelper serverHelper;

	DTLSConnector client;
	InMemoryConnectionStore clientConnectionStore;

	@After
	public void cleanUp() {
		if (serverHelper != null) {
			serverHelper.destroyServer();
		}
		if (client != null) {
			client.destroy();
		}
	}

	private void startServer(boolean enableSni, boolean clientAuthRequired, boolean clientAuthWanted)
			throws IOException, GeneralSecurityException {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setClientAuthenticationRequired(clientAuthRequired)
				.setClientAuthenticationWanted(clientAuthWanted)
				.setLoggingTag("server")
				.setSniEnabled(enableSni);
		serverHelper = new ConnectorHelper();
		serverHelper.startServer(builder);
	}

	private void startClientPsk(boolean enableSni, String hostname, PskStore pskStore) throws Exception {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder().setPskStore(pskStore);
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
				.setMaxConnections(CLIENT_CONNECTION_STORE_CAPACITY);
		DtlsConnectorConfig clientConfig = builder.build();

		client = new DTLSConnector(clientConfig);
		RawData raw = RawData.outbound("Hello World".getBytes(),
				new AddressEndpointContext(serverHelper.serverEndpoint, hostname, null), null, false);
		serverHelper.givenAnEstablishedSession(client, raw, true);
	}

	@Test
	public void testPskHandshakeClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false);
		startClientPsk(false, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testPskHandshakeClientWithoutSniAndServerWithSni() throws Exception {
		startServer(true, true, false);
		startClientPsk(false, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(":" + CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testPskHandshakeWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false);
		startClientPsk(false, SERVERNAME, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testPskHandshakeWithServernameClientWithoutSniAndServerWithSni() throws Exception {
		startServer(true, true, false);
		startClientPsk(false, SERVERNAME, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(":" + CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testPskHandshakeClientWithSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false);
		startClientPsk(true, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testPskHandshakeClientWithSniAndServerWithSni() throws Exception {
		startServer(true, true, false);
		startClientPsk(true, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(":" + CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testPskHandshakeWithServernameClientWithSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false);
		startClientPsk(true, SERVERNAME, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testPskHandshakeWithServernameClientWithSniAndServerWithSni() throws Exception {
		startServer(true, true, false);
		startClientPsk(true, SERVERNAME, new StaticPskStore(SCOPED_CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(SERVERNAME + ":" + SCOPED_CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
	}

	@Test
	public void testRpkHandshakeClientWithSniAndServerWithSni() throws Exception {
		startServer(true, true, false);
		startClientRpk(true, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), startsWith("ni:///sha-256;"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testRpkHandshakeClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false);
		startClientRpk(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), startsWith("ni:///sha-256;"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testRpkHandshakeWithServernameClientWithSniAndServerWithSni() throws Exception {
		startServer(true, true, false);
		startClientRpk(true, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), startsWith("ni:///sha-256;"));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
	}

	@Test
	public void testRpkHandshakeWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false);
		startClientRpk(false, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), startsWith("ni:///sha-256;"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testX509HandshakeClientWithSniAndServerWithSni() throws Exception {
		startServer(true, true, false);
		startClientX509(true, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testX509HandshakeClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false);
		startClientX509(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testX509HandshakeWithServernameClientWithSniAndServerWithSni() throws Exception {
		startServer(true, true, false);
		startClientX509(true, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client"));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
	}

	@Test
	public void testX509HandshakeWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, true, false);
		startClientX509(false, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testRpkHandshakeNoneAuthClientWithSniAndServerWithSni() throws Exception {
		startServer(true, false, false);
		startClientRpk(true, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testRpkHandshakeNoneAuthClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, false, false);
		startClientRpk(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testRpkHandshakeNoneAuthWithServernameClientWithSniAndServerWithSni() throws Exception {
		startServer(true, false, false);
		startClientRpk(true, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
	}

	@Test
	public void testRpkHandshakeNoneAuthWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, false, false);
		startClientRpk(false, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testX509HandshakeNoneAuthClientWithSniAndServerWithSni() throws Exception {
		startServer(true, false, false);
		startClientX509(true, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testX509HandshakeNoneAuthClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, false, false);
		startClientX509(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testX509HandshakeNoneAuthWithServernameClientWithSniAndServerWithSni() throws Exception {
		startServer(true, false, false);
		startClientX509(true, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
	}

	@Test
	public void testX509HandshakeNoneAuthWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, false, false);
		startClientX509(false, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testRpkHandshakeAuthWanted() throws Exception {
		startServer(false, false, true);
		startClientRpk(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testRpkHandshakeAuthWantedAnonymClient() throws Exception {
		startServer(false, false, true);
		startAnonymClientRpk(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testX509HandshakeAuthWanted() throws Exception {
		startServer(false, false, true);
		startClientX509(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testX509HandshakeAuthWantedAnonymClient() throws Exception {
		startServer(false, false, true);
		startAnonymClientX509(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}
}
