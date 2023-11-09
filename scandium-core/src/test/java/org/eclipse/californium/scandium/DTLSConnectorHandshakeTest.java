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
import static org.eclipse.californium.scandium.ConnectorHelper.SERVERNAME2;
import static org.eclipse.californium.scandium.ConnectorHelper.SERVERNAME_WRONG;
import static org.eclipse.californium.scandium.ConnectorHelper.expand;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assume.assumeNotNull;
import static org.junit.Assume.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.auth.AdditionalInfo;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.category.Large;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.rule.LoggingRule;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.JceNames;
import org.eclipse.californium.elements.util.JceProviderUtil;
import org.eclipse.californium.elements.util.SimpleMessageCallback;
import org.eclipse.californium.elements.util.SslContextUtil;
import org.eclipse.californium.elements.util.SslContextUtil.Credentials;
import org.eclipse.californium.elements.util.TestCertificatesTools;
import org.eclipse.californium.elements.util.TestCondition;
import org.eclipse.californium.elements.util.TestConditionTools;
import org.eclipse.californium.elements.util.TestScope;
import org.eclipse.californium.scandium.ConnectorHelper.AlertCatcher;
import org.eclipse.californium.scandium.ConnectorHelper.BuilderSetup;
import org.eclipse.californium.scandium.ConnectorHelper.BuilderSetups;
import org.eclipse.californium.scandium.ConnectorHelper.LatchSessionListener;
import org.eclipse.californium.scandium.ConnectorHelper.TestContext;
import org.eclipse.californium.scandium.auth.ApplicationLevelInfoSupplier;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsSecureRenegotiation;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig.Builder;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.HelloExtension.ExtensionType;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.ClientHandshaker;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.ExtendedMasterSecretMode;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.ThreadLocalKeyPairGenerator;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.dtls.pskstore.AsyncAdvancedPskStore;
import org.eclipse.californium.scandium.dtls.x509.AsyncCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.AsyncNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.CertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.KeyManagerCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.junit.After;
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

/**
 * Verifies behavior of {@link DTLSConnector}.
 * <p>
 * Mainly contains integration test cases verifying the correct interaction
 * between a client and a server during handshakes with and without SNI.
 */
@RunWith(Parameterized.class)
@Category(Large.class)
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

	private static final AdvancedPskStore PSK_STORE = new AdvancedSinglePskStore(CLIENT_IDENTITY,
			CLIENT_IDENTITY_SECRET.getBytes());

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();
	@Rule 
	public LoggingRule logging = new LoggingRule();

	DtlsConnectorConfig.Builder serverBuilder;
	ConnectorHelper serverHelper;

	AsyncAdvancedPskStore serverPskStore;
	AsyncNewAdvancedCertificateVerifier serverVerifier;

	DtlsHealthLogger serverHealth;

	DtlsConnectorConfig.Builder clientBuilder;
	DTLSConnector client;
	TestContext clientTestContext;
	AlertCatcher clientAlertCatcher;
	ApplicationLevelInfoSupplier clientInfoSupplier;
	ApplicationLevelInfoSupplier serverInfoSupplier;
	PrivateKey clientPrivateKey;
	PublicKey clientPublicKey;
	X509Certificate[] clientCertificateChain;
	List<AsyncAdvancedPskStore> clientsPskStores = new ArrayList<>();
	List<AsyncNewAdvancedCertificateVerifier> clientsCertificateVerifiers = new ArrayList<>();

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
	 * Actual DTLS Configuration Builder setup for server.
	 */
	@Parameter(0)
	public BuilderSetup serverBuilderSetup;

	/**
	 * Actual DTLS Configuration Builder setup for client.
	 */
	@Parameter(1)
	public BuilderSetup clientBuilderSetup;

	/**
	 * @return List of DTLS Configuration Builder setup.
	 */
	@Parameters(name = "setup = server {0} / client {1}")
	public static Iterable<BuilderSetup[]> builderSetups() {
		List<BuilderSetup> fragmentModes = Arrays.asList(new BuilderSetup() {

			@Override
			public String toString() {
				return "single-record";
			}

			@Override
			public void setup(Builder builder) {
				builder.set(DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES, false);
			}

		}, new BuilderSetup() {

			@Override
			public String toString() {
				return "multi-handshake-messages";
			}

			@Override
			public void setup(Builder builder) {
				builder.set(DtlsConfig.DTLS_USE_MULTI_HANDSHAKE_MESSAGE_RECORDS, true);
			}

		}, new BuilderSetup() {

			@Override
			public String toString() {
				return "single-handshake-messages";
			}

			@Override
			public void setup(Builder builder) {
				builder.set(DtlsConfig.DTLS_USE_MULTI_HANDSHAKE_MESSAGE_RECORDS, false);
			}
		});
		List<BuilderSetup> sizeModes = Arrays.asList(new BuilderSetup() {

			@Override
			public String toString() {
				return "no record-size-limit";
			}

			@Override
			public void setup(Builder builder) {
				builder.set(DtlsConfig.DTLS_RECORD_SIZE_LIMIT, null);
			}
		}, new BuilderSetup() {

			@Override
			public String toString() {
				return "record-size-limit";
			}

			@Override
			public void setup(Builder builder) {
				builder.set(DtlsConfig.DTLS_RECORD_SIZE_LIMIT, 270);
			}
		});

		List<BuilderSetup> syncModes = Arrays.asList(new BuilderSetup() {

			@Override
			public String toString() {
				return "sync";
			}

			@Override
			public void setup(Builder builder) {
				AdvancedPskStore pskStore = builder.getIncompleteConfig().getAdvancedPskStore();
				if (pskStore instanceof AsyncAdvancedPskStore) {
					((AsyncAdvancedPskStore) pskStore).setDelay(0);
				}
				NewAdvancedCertificateVerifier verifier = builder.getIncompleteConfig()
						.getAdvancedCertificateVerifier();
				if (verifier instanceof AsyncNewAdvancedCertificateVerifier) {
					((AsyncNewAdvancedCertificateVerifier) verifier).setDelay(0);
				}
				CertificateProvider provider = builder.getIncompleteConfig().getCertificateIdentityProvider();
				if (provider instanceof AsyncCertificateProvider) {
					((AsyncCertificateProvider) provider).setDelay(0);
				}
			}
		}, new BuilderSetup() {

			@Override
			public String toString() {
				return "async";
			}

			@Override
			public void setup(Builder builder) {
				AdvancedPskStore pskStore = builder.getIncompleteConfig().getAdvancedPskStore();
				if (pskStore instanceof AsyncAdvancedPskStore) {
					((AsyncAdvancedPskStore) pskStore).setDelay(1);
				}
				NewAdvancedCertificateVerifier verifier = builder.getIncompleteConfig()
						.getAdvancedCertificateVerifier();
				if (verifier instanceof AsyncNewAdvancedCertificateVerifier) {
					((AsyncNewAdvancedCertificateVerifier) verifier).setDelay(1);
				}
				CertificateProvider provider = builder.getIncompleteConfig().getCertificateIdentityProvider();
				if (provider instanceof AsyncCertificateProvider) {
					((AsyncCertificateProvider) provider).setDelay(1);
				}
			}
		});

		List<BuilderSetup[]> combinations = new ArrayList<>();
		if (TestScope.enableIntensiveTests()) {
			BuilderSetup[] serverSetups = expand(fragmentModes);
			BuilderSetup[] clientSetups = expand(fragmentModes, sizeModes);
			for (BuilderSetup server : serverSetups) {
				for (BuilderSetup client : clientSetups) {
					combinations.add(new BuilderSetup[] { server, client });
				}
			}
			for (BuilderSetup setup : syncModes) {
				combinations.add(new BuilderSetup[] { setup, setup });
			}
		} else {
			BuilderSetups server = new BuilderSetups();
			server.add(fragmentModes.get(2));
			server.add(sizeModes.get(1));
			server.add(syncModes.get(1));
			BuilderSetups client = new BuilderSetups();
			client.add(fragmentModes.get(1));
			client.add(sizeModes.get(1));
			client.add(syncModes.get(0));
			combinations.add(new BuilderSetup[] { server, client });
			server = new BuilderSetups();
			server.add(syncModes.get(0));
			client = new BuilderSetups();
			client.add(fragmentModes.get(0));
			client.add(sizeModes.get(0));
			client.add(syncModes.get(1));
			combinations.add(new BuilderSetup[] { server, client });
		}
		return combinations;
	}

	/**
	 * Sets up the fixture.
	 */
	@Before
	public void setUp() {

		serverInfoSupplier = mock(ApplicationLevelInfoSupplier.class);
		when(serverInfoSupplier.getInfo(any(Principal.class), any())).thenReturn(additionalServerInfo);
		clientInfoSupplier = mock(ApplicationLevelInfoSupplier.class);
		when(clientInfoSupplier.getInfo(any(Principal.class), any())).thenReturn(additionalClientInfo);
		clientAlertCatcher = new AlertCatcher();

		serverHelper = new ConnectorHelper(network);
		serverBuilder = serverHelper.serverBuilder;

		serverPskStore = new AsyncAdvancedPskStore(serverHelper.serverPskStore);
		serverPskStore.setDelay(DtlsTestTools.DEFAULT_HANDSHAKE_RESULT_DELAY_MILLIS);
		serverBuilder.setAdvancedPskStore(serverPskStore).setApplicationLevelInfoSupplier(clientInfoSupplier);

		clientBuilder = DtlsConnectorConfig.builder(network.createClientTestConfig());

		clientPrivateKey = DtlsTestTools.getClientPrivateKey();
		clientPublicKey = DtlsTestTools.getClientPublicKey();
		clientCertificateChain = DtlsTestTools.getClientCertificateChain();
	}

	/**
	 * Destroys the server and client.
	 */
	@After
	public void cleanUp() {
		if (serverHelper != null && serverHelper.server != null) {
			assertThat(serverHelper.server.isRunning(), is(true));
			try {
				// wait until no pending jobs left
				TestConditionTools.waitForCondition(6000, 100, TimeUnit.MILLISECONDS, new TestCondition() {

					@Override
					public boolean isFulFilled() throws IllegalStateException {
						return !serverHelper.server.updateHealth();
					}
				});
				TestConditionTools.assertStatisticCounter("jobs left", serverHealth, "pending in jobs", is(0L));
				TestConditionTools.assertStatisticCounter("jobs left", serverHealth, "pending out jobs", is(0L));
				TestConditionTools.assertStatisticCounter("jobs left", serverHealth, "pending handshake jobs", is(0L));
			} catch (InterruptedException e) {
			}
		}
		for (AsyncAdvancedPskStore pskStore : clientsPskStores) {
			pskStore.shutdown();
		}
		clientsPskStores.clear();
		for (AsyncNewAdvancedCertificateVerifier verfier : clientsCertificateVerifiers) {
			verfier.shutdown();
		}
		clientsCertificateVerifiers.clear();
		if (serverPskStore != null) {
			serverPskStore.shutdown();
			serverPskStore = null;
		}
		if (serverVerifier != null) {
			serverVerifier.shutdown();
			serverVerifier = null;
		}
		if (serverHelper != null) {
			if (serverHelper.server != null) {
				serverHelper.server.stop();
				ConnectorHelper.assertReloadConnections("server", serverHelper.server);
			}
			serverHelper.destroyServer();
			serverHelper = null;
		}
		if (client != null) {
			client.stop();
			ConnectorHelper.assertReloadConnections("client", client);
			client.destroy();
			client = null;
		}
	}

	private void assertClientPrincipalHasAdditionalInfo(Principal clientIdentity) {
		ConnectorHelper.assertPrincipalHasAdditionalInfo(clientIdentity, KEY_DEVICE_ID, DEVICE_ID);
	}

	private void assertCidVariant(EndpointContext endpointContext, boolean deprecatedCid, int readCidlength, int writeCidlength) {
		Connection connection = serverHelper.serverConnectionStore.get(endpointContext.getPeerAddress());
		assertThat(connection, is(notNullValue()));
		assertThat(connection.getEstablishedDtlsContext(), is(notNullValue()));
		assertThat(connection.getEstablishedDtlsContext().useDeprecatedCid(), is(deprecatedCid));

		assertThat(endpointContext.get(DtlsEndpointContext.KEY_READ_CONNECTION_ID), is(notNullValue()));
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_READ_CONNECTION_ID).length(), is(readCidlength));
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_WRITE_CONNECTION_ID), is(notNullValue()));
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_WRITE_CONNECTION_ID).length(), is(writeCidlength));
	}

	private void startServer() throws IOException, GeneralSecurityException {

		DtlsConnectorConfig incompleteConfig = serverBuilder.getIncompleteConfig();

		if (incompleteConfig.get(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION)) {
			serverBuilder.setCertificateIdentityProvider(new KeyManagerCertificateProvider(DtlsTestTools.SERVER_NAME,
					DtlsTestTools.getDtlsServerKeyManager(), incompleteConfig.get(DtlsConfig.DTLS_CERTIFICATE_TYPES)));
		}
		if (incompleteConfig.get(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE) != CertificateAuthenticationMode.NONE) {
			if (incompleteConfig.getAdvancedCertificateVerifier() == null) {
				serverVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier.builder()
						.setTrustAllCertificates().setTrustAllRPKs().build();
				serverBuilder.setAdvancedCertificateVerifier(serverVerifier);
				serverVerifier.setDelay(DtlsTestTools.DEFAULT_HANDSHAKE_RESULT_DELAY_MILLIS);
			}
		}
		serverHealth = new DtlsHealthLogger("server");
		serverBuilder.setHealthHandler(serverHealth);
		serverBuilderSetup.setup(serverBuilder);
		serverHelper.startServer();
	}

	private DTLSSession startClientPsk(String hostname) throws Exception {
		AdvancedPskStore pskStore = clientBuilder.getIncompleteConfig().getAdvancedPskStore();
		if (!(pskStore instanceof AsyncAdvancedPskStore)) {
			AsyncAdvancedPskStore clientPskStore = new AsyncAdvancedPskStore(pskStore == null ? PSK_STORE : pskStore);
			clientsPskStores.add(clientPskStore);
			clientBuilder.setAdvancedPskStore(clientPskStore);
		}
		return startClient(hostname);
	}

	private DTLSSession startClientRpk(String hostname) throws Exception {
		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllRPKs().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);
		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier);
		return startClient(hostname);
	}

	private DTLSSession startClientX509(String hostname) throws Exception {
		if (clientBuilder.getIncompleteConfig().getAdvancedCertificateVerifier() == null) {
			AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
					.builder().setTrustAllCertificates().build();
			clientsCertificateVerifiers.add(clientCertificateVerifier);
			clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier);
		}
		return startClient(hostname);
	}

	private void setupClientCertificateIdentity(CertificateType type) {
		SingleCertificateProvider provider;
		if (type == CertificateType.RAW_PUBLIC_KEY) {
			provider = new SingleCertificateProvider(clientPrivateKey, clientPublicKey);
		} else {
			provider = new SingleCertificateProvider(clientPrivateKey, clientCertificateChain);
		}
		provider.setVerifyKeyPair(false);
		clientBuilder.setCertificateIdentityProvider(provider);
	}

	private DTLSSession startClient(String hostname) throws Exception {
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		clientBuilder.setAddress(clientEndpoint).setLoggingTag("client").set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 1)
				.set(DtlsConfig.DTLS_CONNECTOR_THREAD_COUNT, 1)
				.set(DtlsConfig.DTLS_MAX_CONNECTIONS, CLIENT_CONNECTION_STORE_CAPACITY)
				.setApplicationLevelInfoSupplier(serverInfoSupplier);

		clientBuilderSetup.setup(clientBuilder);
		DtlsConnectorConfig clientConfig = clientBuilder.build();

		client = serverHelper.createClient(clientConfig);
		client.setAlertHandler(clientAlertCatcher);
		RawData raw = RawData.outbound("Hello World".getBytes(),
				new AddressEndpointContext(serverHelper.serverEndpoint, hostname, null), null, false);
		clientTestContext = serverHelper.givenAnEstablishedSession(client, raw, true);
		final DTLSSession session = client.getSessionByAddress(serverHelper.serverEndpoint);
		assertThat(session, is(notNullValue()));
		ConnectorHelper.assertPrincipalHasAdditionalInfo(session.getPeerIdentity(), KEY_SERVER_NAME,
				ConnectorHelper.SERVERNAME);
		return session;
	}

	private void startClientFailing() throws Exception {
		startClientFailing(new AddressEndpointContext(serverHelper.serverEndpoint));
	}

	private void startClientFailing(EndpointContext destination) throws Exception {
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		clientBuilder.setAddress(clientEndpoint).setLoggingTag("client").set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 1)
				.set(DtlsConfig.DTLS_CONNECTOR_THREAD_COUNT, 1)
				.set(DtlsConfig.DTLS_MAX_CONNECTIONS, CLIENT_CONNECTION_STORE_CAPACITY);
		clientBuilderSetup.setup(clientBuilder);
		DtlsConnectorConfig clientConfig = clientBuilder.build();

		client = serverHelper.createClient(clientConfig);
		client.setAlertHandler(clientAlertCatcher);
		client.start();
		SimpleMessageCallback callback = new SimpleMessageCallback();
		RawData raw = RawData.outbound("Hello World".getBytes(), destination, callback, false);
		client.send(raw);
		Throwable error = callback.getError(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS));
		assertThat("client side error missing", error, is(notNullValue()));
	}

	@Test
	public void testCipherSuiteOrderedByClientPriority() throws Exception {
		serverHelper.serverBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256,
				CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		startServer();
		// different order then the server
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
				CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8));
	}

	@Test
	public void testPskHandshakeClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer();
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeClientWithoutSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(":" + CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer();
		startClientPsk(SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithServernameClientWithoutSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();
		startClientPsk(SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(":" + CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeClientWithSniAndServerWithoutSni() throws Exception {
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeClientWithSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(":" + CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithServernameClientWithSniAndServerWithoutSni() throws Exception {
		logging.setLoggingLevel("ERROR", ClientHandshaker.class);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startClientPsk(SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithServernameClientWithSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();
		clientBuilder
				.setAdvancedPskStore(
						new AdvancedSinglePskStore(SCOPED_CLIENT_IDENTITY, SCOPED_CLIENT_IDENTITY_SECRET.getBytes()))
				.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startClientPsk(SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(SERVERNAME + ":" + SCOPED_CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testRpkHandshakeClientWithSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), startsWith("ni:///sha-256;"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testRpkHandshakeClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer();
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), startsWith("ni:///sha-256;"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testRpkHandshakeWithServernameClientWithSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), startsWith("ni:///sha-256;"));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testRpkHandshakeWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer();
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), startsWith("ni:///sha-256;"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testX509HandshakeClientWithSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		setupClientCertificateIdentity(CertificateType.X_509);
		DTLSSession session = startClientX509(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertThat(session.getPeerIdentity().getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server"));
	}

	@Test
	public void testX509HandshakeClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer();
		setupClientCertificateIdentity(CertificateType.X_509);
		DTLSSession session = startClientX509(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertThat(session.getPeerIdentity().getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server"));
	}

	@Test
	public void testX509HandshakeWithServernameClientWithSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true)
					.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, true);
		setupClientCertificateIdentity(CertificateType.X_509);
		DTLSSession session = startClientX509(SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client"));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertThat(session.getPeerIdentity().getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server"));
	}

	@Test
	public void testX509HandshakeWithWrongServernameClientWithSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);
		clientBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true)
					.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, true)
					.setAdvancedCertificateVerifier(clientCertificateVerifier);
		setupClientCertificateIdentity(CertificateType.X_509);

		startClientFailing(new AddressEndpointContext(serverHelper.serverEndpoint, SERVERNAME_WRONG, null));

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE)));

		listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE)));
	}

	@Test
	public void testX509HandshakeWithWrongServernameClientWithoutSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);
		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier)
					.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, true);

		startClientFailing(new AddressEndpointContext(serverHelper.serverEndpoint, SERVERNAME_WRONG, null));

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE)));

		listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE)));
	}

	@Test
	public void testX509HandshakeWithServername2ClientWithSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		setupClientCertificateIdentity(CertificateType.X_509);
		DTLSSession session = startClientX509(SERVERNAME2);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client"));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME2));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertThat(session.getPeerIdentity().getName(),
				is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server-ca-rsa"));
	}

	@Test
	public void testX509HandshakeWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		startServer();
		setupClientCertificateIdentity(CertificateType.X_509);
		DTLSSession session = startClientX509(SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client"));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertThat(session.getPeerIdentity().getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server"));
	}

	@Test
	public void testRpkHandshakeNoneAuthClientWithSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class), any());
	}

	@Test
	public void testRpkHandshakeNoneAuthClientWithoutSniAndServerWithoutSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class), any());
	}

	@Test
	public void testRpkHandshakeNoneAuthWithServernameClientWithSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class), any());
	}

	@Test
	public void testRpkHandshakeNoneAuthWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class), any());
	}

	@Test
	public void testX509HandshakeNoneAuthClientWithSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		setupClientCertificateIdentity(CertificateType.X_509);
		DTLSSession session = startClientX509(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class), any());
		assertThat(session.getPeerIdentity().getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server"));
	}

	@Test
	public void testX509HandshakeNoneAuthClientWithoutSniAndServerWithoutSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		setupClientCertificateIdentity(CertificateType.X_509);
		DTLSSession session = startClientX509(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class), any());
		assertThat(session.getPeerIdentity().getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server"));
	}

	@Test
	public void testX509HandshakeNoneAuthWithServernameClientWithSniAndServerWithSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, true);
		setupClientCertificateIdentity(CertificateType.X_509);
		DTLSSession session = startClientX509(SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(SERVERNAME));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class), any());
		assertThat(session.getPeerIdentity().getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server"));
	}

	@Test
	public void testX509HandshakeNoneAuthWithServernameClientWithoutSniAndServerWithoutSni() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		setupClientCertificateIdentity(CertificateType.X_509);
		DTLSSession session = startClientX509(SERVERNAME);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class), any());
		assertThat(session.getPeerIdentity().getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server"));
	}

	@Test
	public void testRpkHandshakeAuthWanted() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED);
		startServer();
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testRpkHandshakeAuthWantedAnonymClient() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED);
		startServer();
		startClientRpk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class), any());
	}

	@Test
	public void testX509HandshakeAuthWanted() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED);
		startServer();
		setupClientCertificateIdentity(CertificateType.X_509);
		DTLSSession session = startClientX509(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertThat(session.getPeerIdentity().getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server"));
	}

	@Test
	public void testX509HandshakeAuthWantedAnonymClient() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED);
		startServer();
		DTLSSession session = startClientX509(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class), any());
		assertThat(session.getPeerIdentity().getName(), is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server"));
	}

	@Test
	public void testX509MixedCertificateChainHandshakeAuthWantedAnonymClient() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getServerCaRsaPrivateKey(),
						DtlsTestTools.getServerCaRsaCertificateChain()));
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false);
		DTLSSession session = startClientX509(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class), any());
		assertThat(session.getPeerIdentity().getName(),
				is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server-ca-rsa"));
	}

	@Test
	public void testX509ServerRsaCertificateChainHandshakeAuthWantedAnonymClient() throws Exception {
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.isSupported()
				? CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				: CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		assumeTrue(cipherSuite.name() + " not support by JCE", cipherSuite.isSupported());

		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, cipherSuite, CipherSuite.TLS_PSK_WITH_AES_128_CCM_8)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getServerRsaPrivateKey(),
						DtlsTestTools.getServerRsaCertificateChain()));
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false)
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, cipherSuite);
		DTLSSession session = startClientX509(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(nullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		verify(clientInfoSupplier, never()).getInfo(any(Principal.class), any());
		assertThat(session.getPeerIdentity().getName(),
				is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server-rsa"));
	}

	@Test
	public void testX509ClientRsaCertificateChainHandshake() throws Exception {
		SignatureAndHashAlgorithm shaRsa = SignatureAndHashAlgorithm.SHA256_WITH_RSA;
		assumeTrue(shaRsa.getJcaName() + " not support by JCE", shaRsa.isSupported());

		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NEEDED);
		startServer();

		clientBuilder.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getClientRsaPrivateKey(),
						DtlsTestTools.getClientRsaCertificateChain()));
		DTLSSession session = startClientX509(null);
		assertThat(session.getPeerIdentity().getName(),
				is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server"));
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		Principal principal = endpointContext.getPeerIdentity();
		assertClientPrincipalHasAdditionalInfo(principal);
		assertThat(principal.getName(),
				is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-client-rsa"));

	}
	@Test
	public void testX509ClientRsaCertificateChainHandshakeFailure() throws Exception {
		SignatureAndHashAlgorithm shaRsa = SignatureAndHashAlgorithm.SHA256_WITH_RSA;
		assumeTrue(shaRsa.getJcaName() + " not support by JCE", shaRsa.isSupported());

		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NEEDED);
		serverBuilder.setAsList(DtlsConfig.DTLS_CERTIFICATE_KEY_ALGORITHMS, CertificateKeyAlgorithm.EC);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getClientRsaPrivateKey(),
						DtlsTestTools.getClientRsaCertificateChain()))
				.setAdvancedCertificateVerifier(clientCertificateVerifier);
		startClientFailing();

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE)));

		listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE)));
	}

	@Test
	public void testX509TrustServerCertificate() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(),
						DtlsTestTools.getServerCertificateChain()));
		startServer();
		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustedCertificates(DtlsTestTools.getServerCertificateChain()[0]).build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);
		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier);
		setupClientCertificateIdentity(CertificateType.X_509);
		DTLSSession session = startClientX509(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertThat(session.getPeerIdentity().getName(),
				is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server"));
	}

	@Test
	public void testPskHandshakeWithCid() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 6);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 4);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertCidVariant(endpointContext, false, 6, 4);
	}

	@Test
	public void testPskHandshakeWithServerCid() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 6);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 0);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertCidVariant(endpointContext, false, 6, 0);
	}

	@Test
	public void testPskHandshakeWithClientCid() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 0);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 4);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertCidVariant(endpointContext, false, 0, 4);
	}

	@Test
	public void testPskHandshakeWithoutServerCid() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 4);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_READ_CONNECTION_ID), is(nullValue()));
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_WRITE_CONNECTION_ID), is(nullValue()));
	}

	@Test
	public void testPskHandshakeWithoutClientCid() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 0);
		startServer();
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_READ_CONNECTION_ID), is(nullValue()));
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_WRITE_CONNECTION_ID), is(nullValue()));
	}

	@SuppressWarnings("deprecation")
	@Test
	public void testPskHandshakeWithDeprecatedCid() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_SUPPORT_DEPRECATED_CID, true)
				.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 6);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 4)
				.set(DtlsConfig.DTLS_USE_DEPRECATED_CID, ExtensionType.CONNECTION_ID_DEPRECATED.getId());
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertCidVariant(endpointContext, true, 6, 4);
	}

	@SuppressWarnings("deprecation")
	@Test
	public void testPskHandshakeWithDeprecatedClientCid() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 6);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 4)
				.set(DtlsConfig.DTLS_USE_DEPRECATED_CID, ExtensionType.CONNECTION_ID_DEPRECATED.getId());
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_READ_CONNECTION_ID), is(nullValue()));
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_WRITE_CONNECTION_ID), is(nullValue()));
	}

	@SuppressWarnings("deprecation")
	@Test
	public void testPskHandshakeWithSupportedDeprecatedCid() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_SUPPORT_DEPRECATED_CID, true)
				.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 6);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_CONNECTION_ID_LENGTH, 4);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
		assertCidVariant(endpointContext, false, 6, 4);
	}

	@Test
	public void testPskHandshakeWithRequiredExtendedMasterSecret() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.REQUIRED);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.REQUIRED);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_EXTENDED_MASTER_SECRET), is(Boolean.TRUE));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithoutExtendedMasterSecret() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.NONE);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.NONE);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithoutExtendedMasterSecretByClient() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.ENABLED);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.NONE);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_EXTENDED_MASTER_SECRET), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithoutExtendedMasterSecretByServer() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.NONE);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.ENABLED);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_EXTENDED_MASTER_SECRET), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithoutExtendedMasterSecretByClientRequiredByServer() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.REQUIRED);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.NONE)
				.setAdvancedPskStore(PSK_STORE);
		startClientFailing();

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));

		alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));
	}

	@Test
	public void testPskHandshakeWithoutExtendedMasterSecretByServerRequiredByClient() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.NONE);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_EXTENDED_MASTER_SECRET_MODE, ExtendedMasterSecretMode.REQUIRED)
				.setAdvancedPskStore(PSK_STORE);
		startClientFailing();

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));

		alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));
	}

	@Test
	public void testPskHandshakeWithoutSecureRenegotiation() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_SECURE_RENEGOTIATION, DtlsSecureRenegotiation.NONE);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_SECURE_RENEGOTIATION, DtlsSecureRenegotiation.NONE);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_SECURE_RENEGOTIATION), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeClientWithoutSecureRenegotiation() throws Exception {
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_SECURE_RENEGOTIATION, DtlsSecureRenegotiation.NONE);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_SECURE_RENEGOTIATION), is(nullValue()));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeWithNeededSecureRenegotiation() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_SECURE_RENEGOTIATION, DtlsSecureRenegotiation.NEEDED);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_SECURE_RENEGOTIATION, DtlsSecureRenegotiation.NEEDED);
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		assertThat(endpointContext.get(DtlsEndpointContext.KEY_SECURE_RENEGOTIATION), is(Boolean.TRUE));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeClientWithoutServerWithNeededSecureRenegotiation() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_SECURE_RENEGOTIATION, DtlsSecureRenegotiation.NEEDED);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_SECURE_RENEGOTIATION, DtlsSecureRenegotiation.NONE)
				.setAdvancedPskStore(PSK_STORE);

		startClientFailing();

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));

		alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));
	}

	@Test
	public void testPskHandshakeClientWithNeededServerWithoutSecureRenegotiation() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_SECURE_RENEGOTIATION, DtlsSecureRenegotiation.NONE);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_SECURE_RENEGOTIATION, DtlsSecureRenegotiation.NEEDED)
				.setAdvancedPskStore(PSK_STORE);

		startClientFailing();

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));

		alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));
	}

	@Test
	public void testPskHandshakeWithoutSession() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_SERVER_USE_SESSION_ID, false)
				.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, false);
		startServer();
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakePskSecret() throws Exception {
		serverPskStore.setSecretMode(false);
		serverBuilder.set(DtlsConfig.DTLS_SERVER_USE_SESSION_ID, false)
				.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, false);
		startServer();
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testPskHandshakeMasterSecret() throws Exception {
		serverPskStore.setSecretMode(true);
		serverBuilder.set(DtlsConfig.DTLS_SERVER_USE_SESSION_ID, false)
				.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE)
				.set(DtlsConfig.DTLS_USE_SERVER_NAME_INDICATION, false);
		startServer();
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(principal.getName(), is(CLIENT_IDENTITY));
		assertClientPrincipalHasAdditionalInfo(principal);
	}

	@Test
	public void testEcdhPskHandshake() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256);
		startClientPsk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256));
	}

	@Test
	public void testPskCbcHandshake() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256);
		startClientPsk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256));
	}

	@Test
	public void testPskCcm8Handshake() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
		startClientPsk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_128_CCM_8));
	}

	@Test
	public void testPsk256Ccm8Handshake() throws Exception {
		assumeTrue("AES256 requires JVM support!", CipherSuite.TLS_PSK_WITH_AES_256_CCM_8.isSupported());
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_PSK_WITH_AES_256_CCM_8);
		startClientPsk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_256_CCM_8));
	}

	@Test
	public void testPskCcmHandshake() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_PSK_WITH_AES_128_CCM);
		startClientPsk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_128_CCM));
	}

	@Test
	public void testPsk256CcmHandshake() throws Exception {
		assumeTrue("AES256 requires JVM support!", CipherSuite.TLS_PSK_WITH_AES_256_CCM.isSupported());
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_PSK_WITH_AES_256_CCM);
		startClientPsk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_256_CCM));
	}

	@Test
	public void testPskGcmHandshake() throws Exception {
		assumeTrue("GCM requires JVM support!", CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256.isSupported());
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256);
		startClientPsk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_PSK_WITH_AES_128_GCM_SHA256));
	}

	@Test
	public void testRpkCbcHandshake() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256));
	}

	@Test
	public void testRpkCcm8Handshake() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
	}

	@Test
	public void testRpk256Ccm8Handshake() throws Exception {
		assumeTrue("AES256 requires JVM support!", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8.isSupported());
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8));
	}

	@Test
	public void testRpkCcmHandshake() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM));
	}

	@Test
	public void testRpk256CcmHandshake() throws Exception {
		assumeTrue("AES256 requires JVM support!", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM.isSupported());
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM));
	}

	@Test
	public void testRpk256CbcHandshake() throws Exception {
		assumeTrue("AES256 requires JVM support!", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.isSupported());
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA));
	}

	@Test
	public void testRpk256Cbc384Handshake() throws Exception {
		assumeTrue("AES256 requires JVM support!", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384.isSupported());
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384));
	}

	@Test
	public void testRpkGcmHandshake() throws Exception {
		assumeTrue("GCM requires JVM support!", CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.isSupported());
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256));
	}

	@Test
	public void testRpkEd25519Handshake() throws Exception {
		assumeTrue("X25519 requires JCE support!", XECDHECryptography.SupportedGroup.X25519.isUsable());
		assumeTrue("ED25519 requires JCE support!", SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519.isSupported());
		List<SignatureAndHashAlgorithm> defaults = new ArrayList<>(SignatureAndHashAlgorithm.DEFAULT);
		defaults.add(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519);
		serverBuilder.set(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, defaults);
		startServer();
		KeyPair keyPair = new ThreadLocalKeyPairGenerator("Ed25519").current().generateKeyPair();
		clientPrivateKey = keyPair.getPrivate();
		clientPublicKey = keyPair.getPublic();
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		startClientRpk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
	}

	@Test
	public void testRpkEd448Handshake() throws Exception {
		assumeTrue("X448 requires JCE support!", XECDHECryptography.SupportedGroup.X448.isUsable());
		assumeTrue("ED448 requires JCE support!", SignatureAndHashAlgorithm.INTRINSIC_WITH_ED448.isSupported());
		List<SignatureAndHashAlgorithm> defaults = new ArrayList<>(SignatureAndHashAlgorithm.DEFAULT);
		defaults.add(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED448);
		serverBuilder.set(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, defaults);
		startServer();
		KeyPair keyPair = new ThreadLocalKeyPairGenerator("Ed448").current().generateKeyPair();
		clientPrivateKey = keyPair.getPrivate();
		clientPublicKey = keyPair.getPublic();
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		startClientRpk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
	}

	@Test
	public void testRpkOpensslEd25519Handshake() throws Exception {
		assumeTrue("X25519 requires JCE support!", XECDHECryptography.SupportedGroup.X25519.isUsable());
		assumeTrue("ED25519 requires JCE support!", SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519.isSupported());
		clientPrivateKey = SslContextUtil.loadPrivateKey(SslContextUtil.CLASSPATH_SCHEME + "certs/ed25519_private.pem",
				null, null, null);
		assertThat(clientPrivateKey, is(notNullValue()));
		clientPublicKey = SslContextUtil.loadPublicKey(SslContextUtil.CLASSPATH_SCHEME + "certs/ed25519_public.pem",
				null, null);
		assertThat(clientPublicKey, is(notNullValue()));

		List<SignatureAndHashAlgorithm> defaults = new ArrayList<>(SignatureAndHashAlgorithm.DEFAULT);
		defaults.add(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519);
		serverBuilder.set(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, defaults);
		startServer();
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
	}

	@Test
	public void testRpkOpensslEd448Handshake() throws Exception {
		assumeTrue("X448 requires JCE support!", XECDHECryptography.SupportedGroup.X448.isUsable());
		assumeTrue("ED448 requires JCE support!", SignatureAndHashAlgorithm.INTRINSIC_WITH_ED448.isSupported());
		clientPrivateKey = SslContextUtil.loadPrivateKey(SslContextUtil.CLASSPATH_SCHEME + "certs/ed448_private.pem",
				null, null, null);
		assertThat(clientPrivateKey, is(notNullValue()));
		clientPublicKey = SslContextUtil.loadPublicKey(SslContextUtil.CLASSPATH_SCHEME + "certs/ed448_public.pem", null,
				null);
		assertThat(clientPublicKey, is(notNullValue()));

		List<SignatureAndHashAlgorithm> defaults = new ArrayList<>(SignatureAndHashAlgorithm.DEFAULT);
		defaults.add(SignatureAndHashAlgorithm.INTRINSIC_WITH_ED448);
		serverBuilder.set(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, defaults);
		startServer();
		clientBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);
		startClientRpk(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
	}

	@Test
	public void testRpkRsaHandshakeSingleProvider() throws Exception {
		assumeTrue("RSA requires JCE support!", JceProviderUtil.isSupported(JceNames.RSA));
		Credentials serverCredentials = TestCertificatesTools.getCredentials("serverrsa");
		assumeNotNull("serverrsa credentials missing!", serverCredentials);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.isSupported()
				? CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				: CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		assumeTrue(cipherSuite.name() + " not support by JCE", cipherSuite.isSupported());

		serverBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, cipherSuite, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256)
				.setCertificateIdentityProvider(new SingleCertificateProvider(serverCredentials.getPrivateKey(),serverCredentials.getPublicKey()))
				.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllRPKs().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false)
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS,
						SignatureAndHashAlgorithm.SHA256_WITH_RSA)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, cipherSuite);

		Credentials clientCredentials = TestCertificatesTools.getCredentials("clientrsa");
		clientPrivateKey = clientCredentials.getPrivateKey();
		clientPublicKey = clientCredentials.getPublicKey();
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);

		String serverPrincipal = new RawPublicKeyIdentity(serverCredentials.getPublicKey()).getName();
		DTLSSession session = startClient(null);
		assertThat(clientTestContext.getCipherSuite(), is(cipherSuite));
		assertThat(session.getPeerIdentity().getName(), is(serverPrincipal));

		String clientPrincipal = new RawPublicKeyIdentity(clientPublicKey).getName();
		DTLSSession serverSession = clientTestContext.getEstablishedServerSession();
		assertThat(serverSession.getPeerIdentity().getName(), is(clientPrincipal));
	}

	@Test
	public void testRpkRsaHandshakeKeyManagerProvider() throws Exception {
		assumeTrue("RSA requires JCE support!", JceProviderUtil.isSupported(JceNames.RSA));
		Credentials serverCredentials = TestCertificatesTools.getCredentials("serverrsa");
		assumeNotNull("serverrsa credentials missing!", serverCredentials);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.isSupported()
				? CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				: CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		assumeTrue(cipherSuite.name() + " not support by JCE", cipherSuite.isSupported());

		serverBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, cipherSuite, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256)
				.setCertificateIdentityProvider(new KeyManagerCertificateProvider(DtlsTestTools.getDtlsServerKeyManager(),
						CertificateType.RAW_PUBLIC_KEY))
				.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllRPKs().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false)
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS,
						SignatureAndHashAlgorithm.SHA256_WITH_RSA)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, cipherSuite);

		Credentials clientCredentials = TestCertificatesTools.getCredentials("clientrsa");
		clientPrivateKey = clientCredentials.getPrivateKey();
		clientPublicKey = clientCredentials.getPublicKey();
		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);

		String serverPrincipal = new RawPublicKeyIdentity(serverCredentials.getPublicKey()).getName();
		DTLSSession session = startClient(null);
		assertThat(clientTestContext.getCipherSuite(), is(cipherSuite));
		assertThat(session.getPeerIdentity().getName(), is(serverPrincipal));

		String clientPrincipal = new RawPublicKeyIdentity(clientPublicKey).getName();
		DTLSSession serverSession = clientTestContext.getEstablishedServerSession();
		assertThat(serverSession.getPeerIdentity().getName(), is(clientPrincipal));
	}

	@Test
	public void testRpkRsaEcdsaMixedHandshakeKeyManagerProvider() throws Exception {
		assumeTrue("RSA requires JCE support!", JceProviderUtil.isSupported(JceNames.RSA));
		Credentials serverCredentials = TestCertificatesTools.getCredentials("serverrsa");
		assumeNotNull("serverrsa credentials missing!", serverCredentials);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.isSupported()
				? CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				: CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		assumeTrue(cipherSuite.name() + " not support by JCE", cipherSuite.isSupported());

		serverBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, cipherSuite, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256)
				.setCertificateIdentityProvider(new KeyManagerCertificateProvider(DtlsTestTools.getDtlsServerKeyManager(),
						CertificateType.RAW_PUBLIC_KEY))
				.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllRPKs().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false)
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, cipherSuite);

		setupClientCertificateIdentity(CertificateType.RAW_PUBLIC_KEY);

		String serverPrincipal = new RawPublicKeyIdentity(serverCredentials.getPublicKey()).getName();
		DTLSSession session = startClient(null);
		assertThat(clientTestContext.getCipherSuite(), is(cipherSuite));
		assertThat(session.getPeerIdentity().getName(), is(serverPrincipal));

		String clientPrincipal = new RawPublicKeyIdentity(clientPublicKey).getName();
		DTLSSession serverSession = clientTestContext.getEstablishedServerSession();
		assertThat(serverSession.getPeerIdentity().getName(), is(clientPrincipal));
	}

	@Test
	public void testRpkRsaAnonymousHandshakeSingleProvider() throws Exception {
		assumeTrue("RSA requires JCE support!", JceProviderUtil.isSupported(JceNames.RSA));
		Credentials serverCredentials = TestCertificatesTools.getCredentials("serverrsa");
		assumeNotNull("serverrsa credentials missing!", serverCredentials);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.isSupported()
				? CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				: CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		assumeTrue(cipherSuite.name() + " not support by JCE", cipherSuite.isSupported());

		serverBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, cipherSuite, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256)
				.setCertificateIdentityProvider(new SingleCertificateProvider(serverCredentials.getPrivateKey(),serverCredentials.getPublicKey()))
				.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllRPKs().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false)
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS,
						SignatureAndHashAlgorithm.SHA256_WITH_RSA)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, cipherSuite);

		String serverPrincipal = new RawPublicKeyIdentity(serverCredentials.getPublicKey()).getName();
		DTLSSession session = startClient(null);
		assertThat(clientTestContext.getCipherSuite(), is(cipherSuite));
		assertThat(session.getPeerIdentity().getName(), is(serverPrincipal));

		DTLSSession serverSession = clientTestContext.getEstablishedServerSession();
		assertThat(serverSession.getPeerIdentity(), is(nullValue()));
	}

	@Test
	public void testX509Ed25519Handshake() throws Exception {
		assumeTrue("X25519 requires JCE support!", XECDHECryptography.SupportedGroup.X25519.isUsable());
		assumeTrue("ED25519 requires JCE support!", SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519.isSupported());
		Credentials credentials = TestCertificatesTools.getCredentials("clienteddsa");
		assumeNotNull("clienteddsa credentials missing!", credentials);

		List<SignatureAndHashAlgorithm> defaults = new ArrayList<>(SignatureAndHashAlgorithm.DEFAULT);
		defaults.add(0, SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519);
		serverBuilder.set(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, defaults).setCertificateIdentityProvider(
				new KeyManagerCertificateProvider(DtlsTestTools.getDtlsServerKeyManager(), CertificateType.X_509));
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS,
						SignatureAndHashAlgorithm.INTRINSIC_WITH_ED25519,
						SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
				.setAsList(DtlsConfig.DTLS_CURVES, SupportedGroup.X25519, SupportedGroup.secp256r1)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

		clientPrivateKey = credentials.getPrivateKey();
		clientCertificateChain = credentials.getCertificateChain();
		setupClientCertificateIdentity(CertificateType.X_509);

		DTLSSession session = startClient(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
		assertThat(session.getPeerIdentity().getName(),
				is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server-eddsa"));
	}

	@Test
	public void testX509RsaHandshake() throws Exception {
		assumeTrue("RSA requires JCE support!", JceProviderUtil.isSupported(JceNames.RSA));
		Credentials credentials = TestCertificatesTools.getCredentials("clientrsa");
		assumeNotNull("clientrsa credentials missing!", credentials);
		CipherSuite cipherSuite = CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.isSupported()
				? CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
				: CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256;
		assumeTrue(cipherSuite.name() + " not support by JCE", cipherSuite.isSupported());

		serverBuilder.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, cipherSuite, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
				CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256).setCertificateIdentityProvider(
						new KeyManagerCertificateProvider(DtlsTestTools.getDtlsServerKeyManager(),
								CertificateType.X_509));
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.set(DtlsConfig.DTLS_VERIFY_SERVER_CERTIFICATES_SUBJECT, false)
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS,
						SignatureAndHashAlgorithm.SHA256_WITH_RSA,
						SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, cipherSuite);

		clientPrivateKey = credentials.getPrivateKey();
		clientCertificateChain = credentials.getCertificateChain();
		setupClientCertificateIdentity(CertificateType.X_509);

		DTLSSession session = startClient(null);
		assertThat(clientTestContext.getCipherSuite(), is(cipherSuite));
		assertThat(session.getPeerIdentity().getName(),
				is("C=CA,L=Ottawa,O=Eclipse IoT,OU=Californium,CN=cf-server-rsa"));
	}

	@Test
	public void testX509HandshakeSignatureAlgorithmsExtensionSha256Ecdsa() throws Exception {
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		setupClientCertificateIdentity(CertificateType.X_509);
		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

		startClient(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
		assertThat(clientTestContext.getEstablishedServerSession().getSignatureAndHashAlgorithm(),
				is(SignatureAndHashAlgorithm.SHA256_WITH_ECDSA));
	}

	@Test
	public void testX509HandshakeSignatureAlgorithmsExtensionSha384Ecdsa() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NEEDED)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS,
						SignatureAndHashAlgorithm.SHA384_WITH_ECDSA,
						SignatureAndHashAlgorithm.SHA256_WITH_ECDSA);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		setupClientCertificateIdentity(CertificateType.X_509);
		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS,
						SignatureAndHashAlgorithm.SHA384_WITH_ECDSA,
						SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

		startClient(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
		assertThat(clientTestContext.getEstablishedServerSession().getSignatureAndHashAlgorithm(),
				is(SignatureAndHashAlgorithm.SHA384_WITH_ECDSA));
	}

	@Test
	public void testX509HandshakeFailingNoCommonSignatureAlgorithms() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED)
			.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS,
					SignatureAndHashAlgorithm.SHA384_WITH_ECDSA,
					SignatureAndHashAlgorithm.SHA256_WITH_ECDSA);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.set(DtlsConfig.DTLS_RECOMMENDED_SIGNATURE_AND_HASH_ALGORITHMS_ONLY, false)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS, SignatureAndHashAlgorithm.SHA1_WITH_ECDSA)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

		startClientFailing();

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));
		assertThat(cause.getMessage(), containsString("fatal alert"));

		alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));

		serverHelper.serverAlertCatcher.resetEvent();
		clientAlertCatcher.resetEvent();
		client.destroy();

		clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier.builder()
				.setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder = DtlsConnectorConfig.builder(clientBuilder.build())
				.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS,
						SignatureAndHashAlgorithm.SHA384_WITH_ECDSA,
						SignatureAndHashAlgorithm.SHA256_WITH_ECDSA)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

		startClient(null);
		assertThat(clientTestContext.getCipherSuite(), is(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8));
		assertThat(clientTestContext.getEstablishedServerSession().getSignatureAndHashAlgorithm(),
				is(SignatureAndHashAlgorithm.SHA384_WITH_ECDSA));
	}

	@Test
	public void testX509HandshakeFailingCertificateSignatureAlgorithm() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED)
		.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS,
				SignatureAndHashAlgorithm.SHA384_WITH_ECDSA,
				SignatureAndHashAlgorithm.SHA256_WITH_ECDSA);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.setAsList(DtlsConfig.DTLS_SIGNATURE_AND_HASH_ALGORITHMS,
						SignatureAndHashAlgorithm.SHA384_WITH_ECDSA)
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

		startClientFailing();

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));
		assertThat(cause.getMessage(), containsString("fatal alert"));

		alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));
	}

	@Test
	public void testX509HandshakeFailingWrongClientCertificate() throws Exception {
		logging.setLoggingLevel("ERROR", SingleCertificateProvider.class);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientCertificateChain = DtlsTestTools.getServerCertificateChain();
		setupClientCertificateIdentity(CertificateType.X_509);
		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier);

		startClientFailing();

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert, is(new AlertMessage(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR)));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));
		assertThat(cause.getMessage(), containsString("fatal alert"));

		alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert, is(new AlertMessage(AlertLevel.FATAL, AlertDescription.DECRYPT_ERROR)));
	}

	@Test
	public void testX509HandshakeFailingExpiredClientCertificate() throws Exception {
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientCertificateChain = DtlsTestTools.getClientExpiredCertificateChain();
		clientPrivateKey = DtlsTestTools.getClientExpiredPrivateKey();
		setupClientCertificateIdentity(CertificateType.X_509);
		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier);

		startClientFailing();

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert, is(new AlertMessage(AlertLevel.FATAL, AlertDescription.CERTIFICATE_EXPIRED)));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));
		assertThat(cause.getMessage(), containsString("fatal alert"));

		alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert, is(new AlertMessage(AlertLevel.FATAL, AlertDescription.CERTIFICATE_EXPIRED)));
	}

	@Test
	public void testX509HandshakeFailingMissingClientCertificate() throws Exception {
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier);

		startClientFailing();

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE)));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));

		alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE)));
	}

	@Test
	public void testX509HandshakeFailingNoCommonCurve() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.set(DtlsConfig.DTLS_RECOMMENDED_CURVES_ONLY, false)
				.setAsListFromText(DtlsConfig.DTLS_CURVES, "secp521r1");

		startClientFailing();

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));

		alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));
	}

	@Test
	public void testX509HandshakeFailingCertificateCurve() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllCertificates().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.set(DtlsConfig.DTLS_RECOMMENDED_CURVES_ONLY, false)
				.setAsListFromText(DtlsConfig.DTLS_CURVES, "secp384r1");

		startClientFailing();

		LatchSessionListener listener = serverHelper.sessionListenerMap.get(client.getAddress());
		assertThat("server side session listener missing", listener, is(notNullValue()));
		Throwable cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("server side handshake failure missing", cause, is(notNullValue()));

		AlertMessage alert = serverHelper.serverAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("server side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));

		listener = serverHelper.sessionListenerMap.get(serverHelper.serverEndpoint);
		assertThat("client side session listener missing", listener, is(notNullValue()));
		cause = listener.waitForSessionFailed(4000, TimeUnit.MILLISECONDS);
		assertThat("client side handshake failure missing", cause, is(notNullValue()));

		alert = clientAlertCatcher.waitForEvent(2000, TimeUnit.MILLISECONDS);
		assertThat("client side alert", alert,
				is(new AlertMessage(AlertLevel.FATAL, AlertDescription.HANDSHAKE_FAILURE)));
	}

	@Test
	public void testServerDropsX509Principal() throws Exception {
		startServer();
		setupClientCertificateIdentity(CertificateType.X_509);
		startClientX509(null);
		clientBuilder = DtlsConnectorConfig.builder(network.createClientTestConfig());
		startClientPsk(null);
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
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.NONE);
		startServer();
		setupClientCertificateIdentity(CertificateType.X_509);
		startClientX509(null);
		int remainingCapacityBefore = serverHelper.serverConnectionStore.remainingCapacity();
		clientBuilder = DtlsConnectorConfig.builder(network.createClientTestConfig());
		startClientPsk(null);
		clientBuilder = DtlsConnectorConfig.builder(network.createClientTestConfig());
		startClientPsk(null);
		EndpointContext endpointContext = serverHelper.serverRawDataProcessor.getClientEndpointContext();
		Principal principal = endpointContext.getPeerIdentity();
		assertThat(principal, is(notNullValue()));
		assertThat(endpointContext.getVirtualHost(), is(nullValue()));
		Future<Void> future = serverHelper.server.startDropConnectionsForPrincipal(principal);
		future.get();
		assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remainingCapacityBefore));
	}

	@Test
	public void testDefaultHandshakeModeNone() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllRPKs().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.set(DtlsConfig.DTLS_DEFAULT_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_NONE)
				.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getClientPrivateKey(),
						DtlsTestTools.getClientPublicKey()));

		EndpointContext endpointContext = new AddressEndpointContext(serverHelper.serverEndpoint);
		startClientFailing(endpointContext);

		SimpleMessageCallback callback = new SimpleMessageCallback();
		RawData raw = RawData.outbound("Hello World, 2!".getBytes(),
				MapBasedEndpointContext.addEntries(endpointContext, DtlsEndpointContext.ATTRIBUTE_HANDSHAKE_MODE_AUTO),
				callback, false);
		client.send(raw);

		endpointContext = callback.getEndpointContext(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS));
		assertThat("client failed to send data", endpointContext, is(notNullValue()));
	}

	@Test
	public void testDefaultHandshakeModeAuto() throws Exception {
		serverBuilder.set(DtlsConfig.DTLS_CLIENT_AUTHENTICATION_MODE, CertificateAuthenticationMode.WANTED);
		startServer();

		AsyncNewAdvancedCertificateVerifier clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier) AsyncNewAdvancedCertificateVerifier
				.builder().setTrustAllRPKs().build();
		clientsCertificateVerifiers.add(clientCertificateVerifier);

		clientBuilder.set(DtlsConfig.DTLS_DEFAULT_HANDSHAKE_MODE, DtlsEndpointContext.HANDSHAKE_MODE_AUTO)
				.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getClientPrivateKey(),
						DtlsTestTools.getClientPublicKey()));

		EndpointContext endpointContext = new AddressEndpointContext(serverHelper.serverEndpoint);
		startClientFailing(MapBasedEndpointContext.addEntries(endpointContext, DtlsEndpointContext.ATTRIBUTE_HANDSHAKE_MODE_NONE));

		SimpleMessageCallback callback = new SimpleMessageCallback();
		RawData raw = RawData.outbound("Hello World, 2!".getBytes(), endpointContext, callback, false);
		client.send(raw);

		endpointContext = callback.getEndpointContext(TimeUnit.SECONDS.toMillis(MAX_TIME_TO_WAIT_SECS));
		assertThat("client failed to send data", endpointContext, is(notNullValue()));
	}

}
