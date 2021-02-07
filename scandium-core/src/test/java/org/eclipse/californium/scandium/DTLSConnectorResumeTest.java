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
import static org.eclipse.californium.scandium.ConnectorHelper.SCOPED_CLIENT_IDENTITY;
import static org.eclipse.californium.scandium.ConnectorHelper.SCOPED_CLIENT_IDENTITY_SECRET;
import static org.eclipse.californium.scandium.ConnectorHelper.SERVERNAME;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext.Attributes;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.auth.PreSharedKeyIdentity;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.eclipse.californium.elements.util.TestScope;
import org.eclipse.californium.elements.util.TestThreadFactory;
import org.eclipse.californium.scandium.ConnectorHelper.AlertCatcher;
import org.eclipse.californium.scandium.ConnectorHelper.BuilderSetup;
import org.eclipse.californium.scandium.ConnectorHelper.LatchDecrementingRawDataChannel;
import org.eclipse.californium.scandium.auth.ApplicationLevelInfoSupplier;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.ExtendedMasterSecretMode;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.dtls.SessionTicket;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedMultiPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.AsyncAdvancedPskStore;
import org.eclipse.californium.scandium.dtls.x509.AsyncNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies behavior of {@link DTLSConnector}.
 * <p>
 * Mainly contains integration test cases verifying the correct interaction
 * between a client and a server during resumption handshakes.
 */
@RunWith(Parameterized.class)
@Category(Medium.class)
public class DTLSConnectorResumeTest {

	public static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnectorResumeTest.class);

	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT,
			DtlsNetworkRule.Mode.NATIVE);

	@ClassRule
	public static ThreadsRule cleanup = new ThreadsRule();

	static ConnectorHelper serverHelper;
	static AsyncAdvancedPskStore serverPskStore;
	static AsyncNewAdvancedCertificateVerifier serverCertificateVerifier;
	static ExecutorService executor;
	static PrivateKey clientPrivateKey;
	static X509Certificate[] clientCertificateChain;
	static AsyncAdvancedPskStore clientPskStore;
	static AsyncNewAdvancedCertificateVerifier clientCertificateVerifier;
	static AdvancedMultiPskStore clientInMemoryPskStore;

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;
	private static final int MAX_TIME_TO_WAIT_SECS = 2;
	private static final String DEVICE_ID = "the-device";
	private static final String KEY_DEVICE_ID = "device-id";

	private static final String SERVERNAME_ALT = "other.test.server";

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	Class<?> clientPrincipalType;
	DTLSConnector client;
	InMemoryConnectionStore clientConnectionStore;
	List<Record> lastReceivedFlight;

	public static interface TypedBuilderSetup extends BuilderSetup {
		Class<?> getPrincipalType();
	}

	/**
	 * Actual DTLS Configuration Builder setup.
	 */
	@Parameter
	public TypedBuilderSetup builderSetup;

	/**
	 * @return List of DTLS Configuration Builder setups.
	 */
	@Parameters(name = "setup = {0}")
	public static Iterable<TypedBuilderSetup> builderSetups() {
		TypedBuilderSetup[] setups = { new TypedBuilderSetup() {

			public String toString() {
				return "PSK-sync-master";
			}

			@Override
			public Class<?> getPrincipalType() {
				return PreSharedKeyIdentity.class;
			}

			@Override
			public void setup(Builder builder) {
				clientPskStore.setDelay(0);
				serverPskStore.setDelay(0);
				clientPskStore.setSecretMode(true);
				serverPskStore.setSecretMode(true);
				builder.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8)
						.setAdvancedPskStore(clientPskStore);
			}

		}, new TypedBuilderSetup() {

			public String toString() {
				return "PSK-async-master";
			}

			@Override
			public Class<?> getPrincipalType() {
				return PreSharedKeyIdentity.class;
			}

			@Override
			public void setup(Builder builder) {
				clientPskStore.setDelay(100);
				serverPskStore.setDelay(100);
				clientPskStore.setSecretMode(true);
				serverPskStore.setSecretMode(true);
				builder.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8)
						.setEnableMultiHandshakeMessageRecords(true).setAdvancedPskStore(clientPskStore);
			}

		}, new TypedBuilderSetup() {

			public String toString() {
				return "PSK-sync-key";
			}

			@Override
			public Class<?> getPrincipalType() {
				return PreSharedKeyIdentity.class;
			}

			@Override
			public void setup(Builder builder) {
				clientPskStore.setDelay(0);
				serverPskStore.setDelay(0);
				clientPskStore.setSecretMode(false);
				serverPskStore.setSecretMode(false);
				builder.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8)
						.setEnableMultiHandshakeMessageRecords(true).setAdvancedPskStore(clientPskStore);
			}

		}, new TypedBuilderSetup() {

			public String toString() {
				return "PSK-async-key";
			}

			@Override
			public Class<?> getPrincipalType() {
				return PreSharedKeyIdentity.class;
			}

			@Override
			public void setup(Builder builder) {
				clientPskStore.setDelay(100);
				serverPskStore.setDelay(100);
				clientPskStore.setSecretMode(false);
				serverPskStore.setSecretMode(false);
				builder.setSupportedCipherSuites(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8)
						.setAdvancedPskStore(clientPskStore);
			}

		}, new TypedBuilderSetup() {

			public String toString() {
				return "PSK-ECDHE-async-master";
			}

			@Override
			public Class<?> getPrincipalType() {
				return PreSharedKeyIdentity.class;
			}

			@Override
			public void setup(Builder builder) {
				clientPskStore.setDelay(100);
				serverPskStore.setDelay(100);
				clientPskStore.setSecretMode(true);
				serverPskStore.setSecretMode(true);
				builder.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256)
						.setEnableMultiHandshakeMessageRecords(true).setAdvancedPskStore(clientPskStore);
			}
			
		}, new TypedBuilderSetup() {

			public String toString() {
				return "PSK-ECDHE-sync-key";
			}

			@Override
			public Class<?> getPrincipalType() {
				return PreSharedKeyIdentity.class;
			}

			@Override
			public void setup(Builder builder) {
				clientPskStore.setDelay(0);
				serverPskStore.setDelay(0);
				clientPskStore.setSecretMode(false);
				serverPskStore.setSecretMode(false);
				builder.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256)
						.setAdvancedPskStore(clientPskStore);
			}

		}, new TypedBuilderSetup() {

			public String toString() {
				return "ECDSA-x509";
			}

			@Override
			public Class<?> getPrincipalType() {
				return X509CertPath.class;
			}

			@Override
			public void setup(Builder builder) {
				clientCertificateVerifier.setDelay(0);
				serverCertificateVerifier.setDelay(0);
				builder.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
						.setIdentity(clientPrivateKey, clientCertificateChain, CertificateType.X_509)
						.setAdvancedCertificateVerifier(clientCertificateVerifier)
						.setTrustCertificateTypes(CertificateType.X_509);
			}
		}, new TypedBuilderSetup() {

			public String toString() {
				return "ECDSA-x509-async";
			}

			@Override
			public Class<?> getPrincipalType() {
				return X509CertPath.class;
			}

			@Override
			public void setup(Builder builder) {
				clientCertificateVerifier.setDelay(100);
				serverCertificateVerifier.setDelay(100);
				builder.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
						.setEnableMultiHandshakeMessageRecords(true)
						.setIdentity(clientPrivateKey, clientCertificateChain, CertificateType.X_509)
						.setAdvancedCertificateVerifier(clientCertificateVerifier)
						.setTrustCertificateTypes(CertificateType.X_509);
			}
		}, new TypedBuilderSetup() {

			public String toString() {
				return "ECDSA-RPK-sync";
			}

			@Override
			public Class<?> getPrincipalType() {
				return RawPublicKeyIdentity.class;
			}

			@Override
			public void setup(Builder builder) {
				builder.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
						.setIdentity(clientPrivateKey, clientCertificateChain, CertificateType.RAW_PUBLIC_KEY)
						.setTrustCertificateTypes(CertificateType.RAW_PUBLIC_KEY)
						.setAdvancedCertificateVerifier(clientCertificateVerifier)
						.setEnableMultiHandshakeMessageRecords(true);
			}
		}, new TypedBuilderSetup() {

			public String toString() {
				return "ECDSA-RPK-async";
			}

			@Override
			public Class<?> getPrincipalType() {
				return RawPublicKeyIdentity.class;
			}

			@Override
			public void setup(Builder builder) {
				clientCertificateVerifier.setDelay(100);
				serverCertificateVerifier.setDelay(100);
				builder.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
						.setIdentity(clientPrivateKey, clientCertificateChain, CertificateType.RAW_PUBLIC_KEY)
						.setTrustCertificateTypes(CertificateType.RAW_PUBLIC_KEY)
						.setAdvancedCertificateVerifier(clientCertificateVerifier)
						.setEnableMultiHandshakeMessageRecords(true);
			}
		} };

		if (TestScope.enableIntensiveTests()) {
			return Arrays.asList(setups);
		} else {
			return Arrays.asList(Arrays.copyOf(setups, 1));
		}
	}

	/**
	 * Starts the server side DTLS connector.
	 * 
	 * @throws Exception if the connector cannot be started.
	 */
	@BeforeClass
	public static void startServer() throws Exception {

		Map<String, Object> info = new HashMap<>();
		info.put(KEY_DEVICE_ID, DEVICE_ID);
		final AdditionalInfo applicationLevelInfo = AdditionalInfo.from(info);

		ApplicationLevelInfoSupplier supplier = new ApplicationLevelInfoSupplier() {

			@Override
			public AdditionalInfo getInfo(Principal clientIdentity, Object customArgument) {
				return applicationLevelInfo;
			}
		};

		AdvancedMultiPskStore pskStore = new AdvancedMultiPskStore();
		pskStore.setKey(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
		pskStore.setKey(SCOPED_CLIENT_IDENTITY, SCOPED_CLIENT_IDENTITY_SECRET.getBytes(), SERVERNAME);
		pskStore.setKey(SCOPED_CLIENT_IDENTITY, SCOPED_CLIENT_IDENTITY_SECRET.getBytes(), SERVERNAME_ALT);
		serverPskStore = new AsyncAdvancedPskStore(pskStore);
		serverCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier.builder()
				.setTrustedCertificates(DtlsTestTools.getTrustedCertificates())
				.setTrustAllRPKs()
				.build();
		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder()
				.setSniEnabled(true)
				.setApplicationLevelInfoSupplier(supplier)
				.setAdvancedCertificateVerifier(serverCertificateVerifier)
				.setAdvancedPskStore(serverPskStore);

		serverHelper = new ConnectorHelper();
		serverHelper.startServer(builder);
		executor = ExecutorsUtil.newFixedThreadPool(2, new TestThreadFactory("DTLS-RESUME-"));
		clientPrivateKey = DtlsTestTools.getClientPrivateKey();
		clientCertificateChain = DtlsTestTools.getClientCertificateChain();

		clientInMemoryPskStore = new AdvancedMultiPskStore();
		clientInMemoryPskStore.addKnownPeer(serverHelper.serverEndpoint, CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
		clientInMemoryPskStore.addKnownPeer(serverHelper.serverEndpoint, SERVERNAME, SCOPED_CLIENT_IDENTITY, SCOPED_CLIENT_IDENTITY_SECRET.getBytes());
		clientInMemoryPskStore.addKnownPeer(serverHelper.serverEndpoint, SERVERNAME_ALT, SCOPED_CLIENT_IDENTITY, SCOPED_CLIENT_IDENTITY_SECRET.getBytes());
		clientPskStore = new AsyncAdvancedPskStore(clientInMemoryPskStore);
		clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier.builder()
				.setTrustedCertificates(DtlsTestTools.getTrustedCertificates())
				.setTrustAllRPKs()
				.build();
	}

	@AfterClass
	public static void tearDown() {
		if (clientPskStore != null) {
			clientPskStore.shutdown();
			clientPskStore = null;
		}
		if (serverPskStore != null) {
			serverPskStore.shutdown();
			serverPskStore = null;
		}
		if (clientCertificateVerifier != null) {
			clientCertificateVerifier.shutdown();
			clientCertificateVerifier = null;
		}
		if (serverCertificateVerifier != null) {
			serverCertificateVerifier.shutdown();
			serverCertificateVerifier = null;
		}
		serverHelper.destroyServer();
		ExecutorsUtil.shutdownExecutorGracefully(100, executor);
	}

	@Before
	public void setUp() throws Exception {
		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);

		DtlsConnectorConfig.Builder builder = createClientConfigBuilder("client", null);
		DtlsConnectorConfig clientConfig = builder.build();

		client = new DTLSConnector(clientConfig, clientConnectionStore);
		client.setExecutor(executor);
	}

	@After
	public void cleanUp() {
		if (client != null) {
			client.stop();
			ConnectorHelper.assertReloadConnections("client", client);
			client.destroy();
		}
		lastReceivedFlight = null;
		serverHelper.cleanUpServer();
	}

	private void autoResumeSetUp(Long timeout) throws Exception {
		cleanUp();
		serverHelper.serverSessionCache.establishedSessionCounter.set(0);
		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);

		DtlsConnectorConfig.Builder builder = createClientConfigBuilder("client-auto-resume", null);
		builder.setAutoResumptionTimeoutMillis(timeout);
		DtlsConnectorConfig clientConfig = builder.build();
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		client.setExecutor(executor);
	}

	private DtlsConnectorConfig.Builder createClientConfigBuilder(String tag, InetSocketAddress clientEndpoint) {
		if (clientEndpoint == null) {
			clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		}
		DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder()
				.setLoggingTag(tag)
				.setAddress(clientEndpoint)
				.setSniEnabled(true)
				.setReceiverThreadCount(1)
				.setConnectionThreadCount(2)
				.setMaxConnections(CLIENT_CONNECTION_STORE_CAPACITY);
		clientPskStore.setResultHandler(null);
		clientCertificateVerifier.setResultHandler(null);
		clientPrincipalType = builderSetup.getPrincipalType();
		builderSetup.setup(builder);
		return builder;
	}

	@Test
	public void testConnectorResumesSessionFromNewConnection() throws Exception {
		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 10000);
		DtlsConnectorConfig clientConfig = createClientConfigBuilder("client-before", clientEndpoint).build();

		client = new DTLSConnector(clientConfig, clientConnectionStore);
		client.setExecutor(executor);

		serverHelper.givenAnEstablishedSession(client);
		client.stop();
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		long time = connection.getEstablishedSession().getCreationTime();

		ByteArrayOutputStream out = new ByteArrayOutputStream();
		client.saveConnections(out, 1000);
		ByteArrayInputStream in = new ByteArrayInputStream(out.toByteArray());
		// create a new client with different inetAddress but with the same session store.
		clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 10001);
		clientConfig = createClientConfigBuilder("client-after", clientEndpoint).build();
		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		LatchDecrementingRawDataChannel clientRawDataChannel = new LatchDecrementingRawDataChannel(1);
		client.setRawDataReceiver(clientRawDataChannel);
		client.loadConnections(in, 0);
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertThat(time, is(connection.getEstablishedSession().getCreationTime()));
		assertClientIdentity(clientPrincipalType);
	}

	@Test
	public void testConnectorAutoResumesSession() throws Exception {

		autoResumeSetUp(500L);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		SessionId sessionId = connection.getSession().getSessionIdentifier();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
		assertThat(connection.isAutoResumptionRequired(500L), is(false));

		Thread.sleep(1000);

		assertThat(connection.isAutoResumptionRequired(500L), is(true));
		
		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertClientIdentity(clientPrincipalType);

		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(2));
	}

	@Test
	public void testConnectorNoAutoResumesSession() throws Exception {

		autoResumeSetUp(1000L);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
		assertThat(connection.isAutoResumptionRequired(1000L), is(false));
		Thread.sleep(750);
		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		Thread.sleep(750);

		assertThat(connection.isAutoResumptionRequired(1000L), is(false));
		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
	}

	@Test
	public void testConnectorSupressAutoResumesSession() throws Exception {
		autoResumeSetUp(500L);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		SessionId sessionId = connection.getSession().getSessionIdentifier();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
		assertClientIdentity(clientPrincipalType);

		Thread.sleep(1000);

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null, new Attributes().add(DtlsEndpointContext.KEY_RESUMPTION_TIMEOUT, -1));
		RawData data = RawData.outbound(msg.getBytes(), context, null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertClientIdentity(clientPrincipalType);

		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
	}

	@Test
	public void testConnectorChangedAutoResumesSession() throws Exception {
		autoResumeSetUp(500L);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		SessionId sessionId = connection.getSession().getSessionIdentifier();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
		assertThat(connection.isAutoResumptionRequired(500L), is(false));

		Thread.sleep(1000);

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null, new Attributes().add(DtlsEndpointContext.KEY_RESUMPTION_TIMEOUT, 10000));
		RawData data = RawData.outbound(msg.getBytes(), context, null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertClientIdentity(clientPrincipalType);

		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));
	}

	@Test
	public void testConnectorResumesSessionFromSharedSessionTicket() throws Exception {
		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client);
		InetSocketAddress clientAddress = clientRawDataChannel.getAddress();
		SessionId establishedSessionId = serverHelper.establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(establishedSessionId));
		client.start();

		// save session ticket
		SessionTicket sessionTicket = serverHelper.establishedServerSession.getSessionTicket();
		assertThat(sessionTicket, is(notNullValue()));
		// remove connection from server's connection store
		serverHelper.remove(clientAddress, true);
		assertThat(serverHelper.serverSessionCache.get(establishedSessionId), is(nullValue()));
		// add ticket to session cache to mimic a fail over from another node
		serverHelper.serverSessionCache.put(establishedSessionId, sessionTicket);

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(establishedSessionId));
		assertClientIdentity(clientPrincipalType);
	}

	@Test
	public void testConnectorResumesSessionFromExistingConnection() throws Exception {
		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client);
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertClientIdentity(clientPrincipalType);
	}

	@Test
	public void testConnectorResumesSessionFromHiddenConnection() throws Exception {
		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client);
		InetSocketAddress clientAddress = clientRawDataChannel.getAddress();
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();
		int remainingCapacity = serverHelper.serverConnectionStore.remainingCapacity();

		// second client with same address
		InMemoryConnectionStore clientConnectionStore2 = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);
		DtlsConnectorConfig.Builder builder2 = createClientConfigBuilder("client-2", clientAddress)
				.setSniEnabled(true)
				.setMaxConnections(CLIENT_CONNECTION_STORE_CAPACITY);
		DtlsConnectorConfig clientConfig2 = builder2.build();

		DTLSConnector client2 = new DTLSConnector(clientConfig2, clientConnectionStore2);
		client2.setExecutor(executor);
		serverHelper.givenAnEstablishedSession(client2);
		int remainingCapacity2 = serverHelper.serverConnectionStore.remainingCapacity();
		assertThat(remainingCapacity2, is(remainingCapacity - 1));

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertClientIdentity(clientPrincipalType);
		remainingCapacity2 = serverHelper.serverConnectionStore.remainingCapacity();
		assertThat(remainingCapacity2, is(remainingCapacity - 1));
	}

	public void testConnectorResumesSessionFromClosedConnection() throws Exception {
		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		long lastHandshakeTime = connection.getEstablishedDtlsContext().getLastHandshakeTime();
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));

		// send close notify, close connection
		client.close(serverHelper.serverEndpoint);

		// close is asynchronous, wait for execution completed.
		for (int loop = 0; loop < 20 && !connection.isResumptionRequired(); ++loop) {
			Thread.sleep(100);
		}
		assertThat(connection.isResumptionRequired(), is(true));

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertClientIdentity(clientPrincipalType);
		assertThat(lastHandshakeTime, is(not(connection.getEstablishedDtlsContext().getLastHandshakeTime())));
	}

	@Test
	public void testConnectorForceResumeSession() throws Exception {
		autoResumeSetUp(null);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		SessionId sessionId = connection.getSession().getSessionIdentifier();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));

		Thread.sleep(500);

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null,
				DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_FORCE);
		RawData data = RawData.outbound(msg.getBytes(), context, null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		assertClientIdentity(clientPrincipalType);

		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(2));
	}

	@Test
	public void testConnectorForceFullHandshake() throws Exception {
		autoResumeSetUp(null);

		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, false);

		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		SessionId sessionId = connection.getSession().getSessionIdentifier();
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(1));

		Thread.sleep(500);

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null,
				DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_FORCE_FULL);
		RawData data = RawData.outbound(msg.getBytes(), context, null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check we use the same session id
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), not(equalTo(sessionId)));
		assertClientIdentity(clientPrincipalType);

		// check, if session is established again
		assertThat(serverHelper.serverSessionCache.establishedSessionCounter.get(), is(2));
	}

	@Test
	public void testConnectorPerformsFullHandshakeWhenResumingNonExistingSession() throws Exception {
		// Do a first handshake
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client);
		InetSocketAddress clientAddress = clientRawDataChannel.getAddress();
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// remove session from server
		serverHelper.remove(clientAddress, true);
		
		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check session id was not equals
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), not(equalTo(sessionId)));
		assertClientIdentity(clientPrincipalType);
	}

	@Test
	public void testConnectorPerformsFullHandshakeWhenResumingWithDifferentSni() throws Exception {

		// Do a first handshake
		RawData raw = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint, SERVERNAME, null), null, false);
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, raw, true);
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint, SERVERNAME_ALT, null), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check session id was not equals
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), not(equalTo(sessionId)));
		assertClientIdentity(clientPrincipalType);
	}

	@Test
	public void testConnectorPerformsFullHandshakeWhenResumingWithEmptySessionId() throws Exception {
		ConnectorHelper serverWithoutSessionId = new ConnectorHelper();
		try {
			DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder()
					.setNoServerSessionId(true)
					.setSniEnabled(true);
			serverWithoutSessionId.startServer(builder);

			clientInMemoryPskStore.addKnownPeer(serverWithoutSessionId.serverEndpoint, CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
			clientInMemoryPskStore.addKnownPeer(serverWithoutSessionId.serverEndpoint, SERVERNAME, SCOPED_CLIENT_IDENTITY, SCOPED_CLIENT_IDENTITY_SECRET.getBytes());
			clientInMemoryPskStore.addKnownPeer(serverWithoutSessionId.serverEndpoint, SERVERNAME_ALT, SCOPED_CLIENT_IDENTITY, SCOPED_CLIENT_IDENTITY_SECRET.getBytes());

			// Do a first handshake
			RawData raw = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(serverWithoutSessionId.serverEndpoint, SERVERNAME, null), null, false);
			LatchDecrementingRawDataChannel clientRawDataChannel = serverWithoutSessionId
					.givenAnEstablishedSession(client, raw, true);
			SessionId sessionId = serverWithoutSessionId.establishedServerSession.getSessionIdentifier();
			assertTrue("session id must be empty", sessionId.isEmpty());

			// Force a resume session the next time we send data
			client.forceResumeSessionFor(serverWithoutSessionId.serverEndpoint);
			Connection connection = clientConnectionStore.get(serverWithoutSessionId.serverEndpoint);
			assertTrue(connection.getEstablishedSession().getSessionIdentifier().isEmpty());
			long time = connection.getEstablishedSession().getCreationTime();
			client.start();

			// Prepare message sending
			final String msg = "Hello Again";
			clientRawDataChannel.setLatchCount(1);

			// send message
			RawData data = RawData.outbound(msg.getBytes(),
					new AddressEndpointContext(serverWithoutSessionId.serverEndpoint, SERVERNAME, null), null, false);
			client.send(data);
			assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// check session id was not equals
			connection = clientConnectionStore.get(serverWithoutSessionId.serverEndpoint);
			assertTrue(connection.getEstablishedSession().getSessionIdentifier().isEmpty());
			assertThat(time, is(not(connection.getEstablishedSession().getCreationTime())));
		} finally {
			serverWithoutSessionId.destroyServer();
		}
	}

	@Test
	public void testConnectorFailsWhenResumingWithoutExtendedMasterSecret() throws Exception {
		client.destroy();

		DtlsConnectorConfig.Builder builder = createClientConfigBuilder("client", null);
		builder.setExtendedMasterSecretMode(ExtendedMasterSecretMode.NONE);
		DtlsConnectorConfig clientConfig = builder.build();

		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		client.setExecutor(executor);
		AlertCatcher clientAlertCatcher = new AlertCatcher();
		client.setAlertHandler(clientAlertCatcher);

		// Do a first handshake
		RawData raw = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint, SERVERNAME, null), null, false);
		LatchDecrementingRawDataChannel clientRawDataChannel = serverHelper.givenAnEstablishedSession(client, raw, true);
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));
		long time = connection.getEstablishedSession().getCreationTime();
		client.start();

		// Prepare message sending
		final String msg = "Hello Again";
		clientRawDataChannel.setLatchCount(1);

		// send message
		RawData data = RawData.outbound(msg.getBytes(), new AddressEndpointContext(serverHelper.serverEndpoint, SERVERNAME, null), null, false);
		client.send(data);
		assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		// check session id was not equals
		connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertTrue(connection.getEstablishedSession().getSessionIdentifier().isEmpty());
		assertThat(time, is(not(connection.getEstablishedSession().getCreationTime())));

	}

	@Test
	public void testConnectorPerformsFullHandshakeWhenResumingWithExtendedMasterSecret() throws Exception {
		client.destroy();

		DtlsConnectorConfig.Builder clientBuilder = createClientConfigBuilder("client", null);
		clientBuilder.setExtendedMasterSecretMode(ExtendedMasterSecretMode.ENABLED);
		DtlsConnectorConfig clientConfig = clientBuilder.build();

		clientConnectionStore = new InMemoryConnectionStore(CLIENT_CONNECTION_STORE_CAPACITY, 60);
		client = new DTLSConnector(clientConfig, clientConnectionStore);
		client.setExecutor(executor);

		ConnectorHelper serverWithoutExtendedMasterSecret = new ConnectorHelper();
		try {
			DtlsConnectorConfig.Builder builder = DtlsConnectorConfig.builder()
					.setSniEnabled(true)
					.setExtendedMasterSecretMode(ExtendedMasterSecretMode.NONE);
			serverWithoutExtendedMasterSecret.startServer(builder);

			clientInMemoryPskStore.addKnownPeer(serverWithoutExtendedMasterSecret.serverEndpoint, CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
			clientInMemoryPskStore.addKnownPeer(serverWithoutExtendedMasterSecret.serverEndpoint, SERVERNAME, SCOPED_CLIENT_IDENTITY, SCOPED_CLIENT_IDENTITY_SECRET.getBytes());
			clientInMemoryPskStore.addKnownPeer(serverWithoutExtendedMasterSecret.serverEndpoint, SERVERNAME_ALT, SCOPED_CLIENT_IDENTITY, SCOPED_CLIENT_IDENTITY_SECRET.getBytes());

			// Do a first handshake
			RawData raw = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(serverWithoutExtendedMasterSecret.serverEndpoint, SERVERNAME, null), null, false);
			LatchDecrementingRawDataChannel clientRawDataChannel = serverWithoutExtendedMasterSecret
					.givenAnEstablishedSession(client, raw, true);
			SessionId sessionId = serverWithoutExtendedMasterSecret.establishedServerSession.getSessionIdentifier();
			assertThat("session id must not be empty", sessionId.isEmpty(), is(false));

			// Force a resume session the next time we send data
			client.forceResumeSessionFor(serverWithoutExtendedMasterSecret.serverEndpoint);
			Connection connection = clientConnectionStore.get(serverWithoutExtendedMasterSecret.serverEndpoint);
			assertFalse(connection.getEstablishedSession().getSessionIdentifier().isEmpty());
			long time = connection.getEstablishedSession().getCreationTime();
			client.start();

			// Prepare message sending
			final String msg = "Hello Again";
			clientRawDataChannel.setLatchCount(1);

			// send message
			RawData data = RawData.outbound(msg.getBytes(),
					new AddressEndpointContext(serverWithoutExtendedMasterSecret.serverEndpoint, SERVERNAME, null), null, false);
			client.send(data);
			assertTrue(clientRawDataChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// check session id was not equals
			connection = clientConnectionStore.get(serverWithoutExtendedMasterSecret.serverEndpoint);
			assertFalse(connection.getEstablishedSession().getSessionIdentifier().isEmpty());
			assertThat(time, is(not(connection.getEstablishedSession().getCreationTime())));
			assertThat(sessionId, is(not(connection.getEstablishedSession().getSessionIdentifier())));
		} finally {
			serverWithoutExtendedMasterSecret.destroyServer();
		}
	}

	@Test
	public void testConnectorSupressHandshake() throws Exception {
		autoResumeSetUp(null);

		// suppress handshake
		SimpleMessageCallback callback = new SimpleMessageCallback(1, false);
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null,
				DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_NONE);
		RawData raw = RawData.outbound("Hello World".getBytes(), context, callback, false);

		client.start();
		client.send(raw);
		assertNotNull(callback.getError(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS)));
		Connection con = serverHelper.serverConnectionStore.get(client.getAddress());
		assertNull(con);
	}

	@Test
	public void testConnectorRequiresResumptionSupressHandshake() throws Exception {
		// Do a first handshake
		serverHelper.givenAnEstablishedSession(client);
		SessionId sessionId = serverHelper.establishedServerSession.getSessionIdentifier();

		// Force a resume session the next time we send data
		client.forceResumeSessionFor(serverHelper.serverEndpoint);
		Connection connection = clientConnectionStore.get(serverHelper.serverEndpoint);
		assertThat(connection.getEstablishedSession().getSessionIdentifier(), is(sessionId));

		// suppress handshake
		SimpleMessageCallback callback = new SimpleMessageCallback(1, false);
		EndpointContext context = new MapBasedEndpointContext(serverHelper.serverEndpoint, null,
				DtlsEndpointContext.KEY_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_NONE);
		RawData raw = RawData.outbound("Hello World".getBytes(), context, callback, false);
		client.start();
		client.send(raw);
		assertNotNull(callback.getError(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS)));
		Connection con = serverHelper.serverConnectionStore.get(client.getAddress());
		assertNull(con);
	}

	private void assertClientIdentity(final Class<?> principalType) {

		Principal clientIdentity = serverHelper.serverRawDataProcessor.getClientEndpointContext().getPeerIdentity();
		// assert that client identity is of given type
		if (principalType == null) {
			assertThat(clientIdentity, is(nullValue()));
		} else {
			assertThat(clientIdentity, instanceOf(principalType));
			ConnectorHelper.assertPrincipalHasAdditionalInfo(clientIdentity, KEY_DEVICE_ID, DEVICE_ID);
		}
	}

}
