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
import static org.junit.Assume.*;
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
import org.eclipse.californium.scandium.dtls.ConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
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

	private void startServer(boolean enableSni, boolean clientAuthRequired, boolean clientAuthWanted, ConnectionIdGenerator cidGenerator)
			throws IOException, GeneralSecurityException {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setClientAuthenticationRequired(clientAuthRequired)
				.setClientAuthenticationWanted(clientAuthWanted)
				.setConnectionIdGenerator(cidGenerator)
				.setLoggingTag("server")
				.setSniEnabled(enableSni);
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
				.setMaxConnections(CLIENT_CONNECTION_STORE_CAPACITY);
		DtlsConnectorConfig clientConfig = builder.build();

		client = new DTLSConnector(clientConfig);
		RawData raw = RawData.outbound("Hello World".getBytes(),
				new AddressEndpointContext(serverHelper.serverEndpoint, hostname, null), null, false);
		serverHelper.givenAnEstablishedSession(client, raw, true);
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
	}

	@Test
	public void testPskHandshakeWithServernameClientWithSniAndServerWithSni() throws Exception {
		startServer(true, true, false, null);
		startClientPsk(true, SERVERNAME, null, new StaticPskStore(SCOPED_CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(SERVERNAME + ":" + SCOPED_CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
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
	}

	@Test
	public void testRpkHandshakeNoneAuthClientWithSniAndServerWithSni() throws Exception {
		startServer(true, false, false, null);
		startClientRpk(true, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testRpkHandshakeNoneAuthClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, false, false, null);
		startClientRpk(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testRpkHandshakeNoneAuthWithServernameClientWithSniAndServerWithSni() throws Exception {
		startServer(true, false, false, null);
		startClientRpk(true, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
	}

	@Test
	public void testRpkHandshakeNoneAuthWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, false, false, null);
		startClientRpk(false, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testX509HandshakeNoneAuthClientWithSniAndServerWithSni() throws Exception {
		startServer(true, false, false, null);
		startClientX509(true, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testX509HandshakeNoneAuthClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, false, false, null);
		startClientX509(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testX509HandshakeNoneAuthWithServernameClientWithSniAndServerWithSni() throws Exception {
		startServer(true, false, false, null);
		startClientX509(true, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
	}

	@Test
	public void testX509HandshakeNoneAuthWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer(false, false, false, null);
		startClientX509(false, SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testRpkHandshakeAuthWanted() throws Exception {
		startServer(false, false, true, null);
		startClientRpk(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testRpkHandshakeAuthWantedAnonymClient() throws Exception {
		startServer(false, false, true, null);
		startAnonymClientRpk(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testX509HandshakeAuthWanted() throws Exception {
		startServer(false, false, true, null);
		startClientX509(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
	}

	@Test
	public void testX509HandshakeAuthWantedAnonymClient() throws Exception {
		startServer(false, false, true, null);
		startAnonymClientX509(false, null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
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
	}

	@Test
	public void testPskHandshakeWithoutSession() throws Exception {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
				.setClientAuthenticationRequired(false)
				.setClientAuthenticationWanted(false)
				.setSniEnabled(false)
				.setNoServerSessionId(true)
				.setLoggingTag("server");
		startServer(builder);
		startClientPsk(false, null, null, new StaticPskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
	}

	@Test
	public void testEcdhPskHandshake() throws Exception {
		startServer(false, false,  false,  null);
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder()
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
}
