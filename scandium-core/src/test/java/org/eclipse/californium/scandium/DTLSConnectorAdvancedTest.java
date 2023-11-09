/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *                                                    Update to use ConnectorHelper
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce waitForFlightReceived
 *                                                    with additional retransmission
 *                                                    compensation for faster timeouts
 *    Achim Kraus (Bosch Software Innovations GmbH) - add test for timeout of handshaker
 *                                                    with stopped retransmission
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.eclipse.californium.scandium.ConnectorHelper.CLIENT_IDENTITY;
import static org.eclipse.californium.scandium.ConnectorHelper.CLIENT_IDENTITY_SECRET;
import static org.eclipse.californium.scandium.ConnectorHelper.LOCAL;
import static org.eclipse.californium.scandium.ConnectorHelper.SCOPED_CLIENT_IDENTITY;
import static org.eclipse.californium.scandium.ConnectorHelper.SCOPED_CLIENT_IDENTITY_SECRET;
import static org.eclipse.californium.scandium.ConnectorHelper.SERVERNAME;
import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.number.OrderingComparison.greaterThan;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.auth.RawPublicKeyIdentity;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.rule.LoggingRule;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.elements.rule.ThreadsRule;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.SerialExecutor;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.TestConditionTools;
import org.eclipse.californium.elements.util.TestScheduledExecutorService;
import org.eclipse.californium.elements.util.TestScope;
import org.eclipse.californium.elements.util.TestThreadFactory;
import org.eclipse.californium.scandium.ConnectorHelper.LatchSessionListener;
import org.eclipse.californium.scandium.ConnectorHelper.RecordCollectorDataHandler;
import org.eclipse.californium.scandium.ConnectorHelper.SessionState;
import org.eclipse.californium.scandium.ConnectorHelper.UdpConnector;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AdversaryClientHandshaker;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.ApplicationMessage;
import org.eclipse.californium.scandium.dtls.CertificateIdentityResult;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.CertificateVerificationResult;
import org.eclipse.californium.scandium.dtls.ClientHandshaker;
import org.eclipse.californium.scandium.dtls.ClientHello;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.ConnectionId;
import org.eclipse.californium.scandium.dtls.ConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.ContentType;
import org.eclipse.californium.scandium.dtls.DTLSConnectionState;
import org.eclipse.californium.scandium.dtls.DTLSContext;
import org.eclipse.californium.scandium.dtls.DTLSMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DtlsHandshakeTimeoutException;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.HelloVerifyRequest;
import org.eclipse.californium.scandium.dtls.PskPublicInformation;
import org.eclipse.californium.scandium.dtls.PskSecretResult;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.RecordLayer;
import org.eclipse.californium.scandium.dtls.ResumingClientHandshaker;
import org.eclipse.californium.scandium.dtls.ResumingServerHandshaker;
import org.eclipse.californium.scandium.dtls.ResumptionSupportingConnectionStore;
import org.eclipse.californium.scandium.dtls.ResumptionVerificationResult;
import org.eclipse.californium.scandium.dtls.ServerHandshaker;
import org.eclipse.californium.scandium.dtls.SessionId;
import org.eclipse.californium.scandium.dtls.SignatureAndHashAlgorithm;
import org.eclipse.californium.scandium.dtls.SingleNodeConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.CertificateKeyAlgorithm;
import org.eclipse.californium.scandium.dtls.cipher.RandomManager;
import org.eclipse.californium.scandium.dtls.cipher.XECDHECryptography.SupportedGroup;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedMultiPskStore;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedSinglePskStore;
import org.eclipse.californium.scandium.dtls.pskstore.AsyncAdvancedPskStore;
import org.eclipse.californium.scandium.dtls.resumption.AsyncResumptionVerifier;
import org.eclipse.californium.scandium.dtls.x509.AsyncCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.AsyncNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;
import org.eclipse.californium.scandium.util.ServerNames;
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
 * between a client and a server during handshakes including unusual message
 * order and timeouts.
 */
@RunWith(Parameterized.class)
@Category(Medium.class)
public class DTLSConnectorAdvancedTest {

	public static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnectorAdvancedTest.class);

	@ClassRule
	public static DtlsNetworkRule network = new DtlsNetworkRule(DtlsNetworkRule.Mode.DIRECT,
			DtlsNetworkRule.Mode.NATIVE);

	@ClassRule
	public static ThreadsRule cleanup = new ThreadsRule();

	@Rule
	public TestNameLoggerRule names = new TestNameLoggerRule();

	@Rule
	public TestTimeRule time = new TestTimeRule();

	@Rule 
	public LoggingRule logging = new LoggingRule();

	private static final int CLIENT_CONNECTION_STORE_CAPACITY = 5;
	private static final int MAX_TIME_TO_WAIT_SECS = 2;
	private static final int RETRANSMISSION_TIMEOUT_MS = 400;
	private static final int MAX_RETRANSMISSIONS = 2;
	private static final int HANDSHAKE_EXPIRES_MS = RETRANSMISSION_TIMEOUT_MS * ((2 << MAX_RETRANSMISSIONS) + 1);

	static AsyncAdvancedPskStore serverPskStore;
	static AsyncCertificateProvider serverCertificateProvider;
	static AsyncNewAdvancedCertificateVerifier serverCertificateVerifier;
	static AsyncResumptionVerifier serverResumptionVerifier;
	static int pskHandshakeResponses = 1;
	static int certificateHandshakeResponses = 1;
	static int verifyHandshakeResponses = 1;
	static int resumeHandshakeResponses = 1;
	static ConnectorHelper serverHelper;
	static DtlsHealthLogger serverHealth;
	static DtlsHealthLogger clientHealth;

	static TestScheduledExecutorService timer;
	static ExecutorService executor;
	static ConnectionIdGenerator serverCidGenerator;
	static DtlsConnectorConfig serverConfigSingleRecord;

	ConnectorHelper alternativeServerHelper;
	AsyncAdvancedPskStore clientPskStore;
	AsyncNewAdvancedCertificateVerifier clientCertificateVerifier;
	DtlsConnectorConfig.Builder clientConfigBuilder;
	DTLSConnector client;
	ResumptionSupportingConnectionStore clientConnectionStore;
	List<Record> lastReceivedFlight;
	List<Record> lastSentFlight;

	@BeforeClass
	public static void loadKeys() throws IOException, GeneralSecurityException {
		serverHelper = new ConnectorHelper(network);
		serverHealth = new DtlsHealthLogger("server");
		serverCidGenerator = new SingleNodeConnectionIdGenerator(6);
		AdvancedMultiPskStore pskStore = new AdvancedMultiPskStore();
		pskStore.setKey(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
		pskStore.setKey(SCOPED_CLIENT_IDENTITY, SCOPED_CLIENT_IDENTITY_SECRET.getBytes(), SERVERNAME);
		serverPskStore = new AsyncAdvancedPskStore(pskStore) {

			@Override
			public PskSecretResult requestPskSecretResult(final ConnectionId cid, final ServerNames serverNames,
					final PskPublicInformation identity, final String hmacAlgorithm, SecretKey otherSecret, byte[] seed,
					boolean useExtendedMasterSecret) {
				LOGGER.info("get PSK secrets");
				PskSecretResult result = null;
				if (0 < pskHandshakeResponses) {
					result = super.requestPskSecretResult(cid, serverNames, identity, hmacAlgorithm, otherSecret, seed,
							useExtendedMasterSecret);
					if (1 < pskHandshakeResponses) {
						final int delay = getDelay();
						try {
							setDelay(1);
							for (int index = 1; index < pskHandshakeResponses; ++index) {
								super.requestPskSecretResult(cid, serverNames, identity, hmacAlgorithm, otherSecret,
										seed, useExtendedMasterSecret);
							}
						} finally {
							setDelay(delay);
						}
					}
				}
				return result;
			}
		};

		serverCertificateVerifier = new AsyncNewAdvancedCertificateVerifier(DtlsTestTools.getTrustedCertificates(),
				new RawPublicKeyIdentity[0], null) {

			@Override
			public CertificateVerificationResult verifyCertificate(final ConnectionId cid, final ServerNames serverName,
					InetSocketAddress remotePeer, final boolean clientUsage,
					boolean verifyDestination, final boolean truncateCertificatePath, final CertificateMessage message) {
				LOGGER.info("verify certificate");
				CertificateVerificationResult result = null;
				if (0 < verifyHandshakeResponses) {
					result = super.verifyCertificate(cid, serverName, remotePeer, clientUsage, verifyDestination, truncateCertificatePath, message);
					if (1 < verifyHandshakeResponses) {
						final int delay = getDelay();
						try {
							setDelay(1);
							for (int index = 1; index < verifyHandshakeResponses; ++index) {
								super.verifyCertificate(cid, serverName, remotePeer, clientUsage, verifyDestination, truncateCertificatePath, message);
							}
						} finally {
							setDelay(delay);
						}
					}
				}
				return result;
			}
		};

		serverResumptionVerifier = new AsyncResumptionVerifier() {
			@Override
			public ResumptionVerificationResult verifyResumptionRequest(final ConnectionId cid, final ServerNames serverName,
					final SessionId sessionId) {
				LOGGER.info("verify resumption");
				ResumptionVerificationResult result = null;
				if (0 < resumeHandshakeResponses) {
					result = super.verifyResumptionRequest(cid, serverName, sessionId);
					if (1 < resumeHandshakeResponses) {
						final int delay = getDelay();
						
						try {
							setDelay(1);
							for (int index = 1; index < resumeHandshakeResponses; ++index) {
								super.verifyResumptionRequest(cid, serverName, sessionId);
							}
						} finally {
							setDelay(delay);
						}
					}
				}
				return result;
			}
		};

		serverCertificateProvider = new AsyncCertificateProvider(DtlsTestTools.getPrivateKey(),
				DtlsTestTools.getServerCertificateChain(), CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509) {

			@Override
			public CertificateIdentityResult requestCertificateIdentity(final ConnectionId cid, final boolean client,
					final List<X500Principal> issuers, final ServerNames serverName,
					final List<CertificateKeyAlgorithm> certificateKeyAlgorithms,
					final List<SignatureAndHashAlgorithm> signaturesAndHashAlgorithms,
					final List<SupportedGroup> curves) {
				LOGGER.info("verify resumption");
				CertificateIdentityResult result = null;
				if (0 < certificateHandshakeResponses) {
					result = super.requestCertificateIdentity(cid, client, issuers, serverName,
							certificateKeyAlgorithms, signaturesAndHashAlgorithms, curves);
					if (1 < certificateHandshakeResponses) {
						final int delay = getDelay();
						try {
							setDelay(1);
							for (int index = 1; index < certificateHandshakeResponses; ++index) {
								super.requestCertificateIdentity(cid, client, issuers, serverName,
										certificateKeyAlgorithms, signaturesAndHashAlgorithms, curves);
							}
						} finally {
							setDelay(delay);
						}
					}
				}
				return result;
			}
		};

		serverHelper.serverBuilder
				.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, RETRANSMISSION_TIMEOUT_MS, TimeUnit.MILLISECONDS)
				.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, MAX_RETRANSMISSIONS)
				.set(DtlsConfig.DTLS_MAX_TRANSMISSION_UNIT, 1024)
				.setConnectionIdGenerator(serverCidGenerator)
				.setHealthHandler(serverHealth)
				.setAdvancedPskStore(serverPskStore)
				.setCertificateIdentityProvider(serverCertificateProvider)
				.setAdvancedCertificateVerifier(serverCertificateVerifier)
				.setResumptionVerifier(serverResumptionVerifier);
		serverHelper.startServer();

		serverConfigSingleRecord = DtlsConnectorConfig.builder(serverHelper.serverConfig)
				.set(DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES, false)
				.build();
		executor = ExecutorsUtil.newFixedThreadPool(2, new TestThreadFactory("DTLS-ADVANCED-"));
		timer = new TestScheduledExecutorService();
		clientHealth = new DtlsHealthLogger("client");
	}

	@AfterClass
	public static void tearDown() {
		if (serverPskStore != null) {
			serverPskStore.shutdown();
			serverPskStore = null;
		}
		if (serverCertificateVerifier != null) {
			serverCertificateVerifier.shutdown();
			serverCertificateVerifier = null;
		}
		if (serverResumptionVerifier != null) {
			serverResumptionVerifier.shutdown();
			serverResumptionVerifier = null;
		}
		if (serverCertificateProvider != null) {
			serverCertificateProvider.shutdown();
			serverCertificateProvider = null;
		}
		if (serverHelper != null) {
			serverHelper.destroyServer();
			serverHelper = null;
		}
		if (timer != null) {
			timer.shutdown();
			timer = null;
		}
		if (executor != null) {
			ExecutorsUtil.shutdownExecutorGracefully(100, executor);
			executor = null;
		}
	}

	/**
	 * Actual cipher suite.
	 */
	@Parameter
	public ConnectionIdGenerator clientCidGenerator;

	/**
	 * @return List of cipher suites.
	 */
	@Parameters(name = "cid = {0}")
	public static Iterable<ConnectionIdGenerator> cidParams() {
		if (TestScope.enableIntensiveTests()) {
			return Arrays.asList((ConnectionIdGenerator) null
			, new SingleNodeConnectionIdGenerator(0) {

				public String toString() {
					return "cid supported";
				}
			}, new SingleNodeConnectionIdGenerator(5) {

				public String toString() {
					return "cid used";
				}
			});
		} else {
			return Arrays.asList((ConnectionIdGenerator) null);
		}
	}

	@Before
	public void setUp() throws Exception {
		pskHandshakeResponses = 1;
		certificateHandshakeResponses = 1;
		verifyHandshakeResponses = 1;
		resumeHandshakeResponses = 1;

		clientCertificateVerifier = (AsyncNewAdvancedCertificateVerifier)AsyncNewAdvancedCertificateVerifier.builder()
				.setTrustedCertificates(DtlsTestTools.getTrustedCertificates())
				.setTrustAllRPKs()
				.build();
		clientCertificateVerifier.setDelay(0);
		clientConfigBuilder = ConnectorHelper.newClientConfigBuilder(network)
				.set(DtlsConfig.DTLS_MAX_CONNECTIONS, CLIENT_CONNECTION_STORE_CAPACITY)
				.set(DtlsConfig.DTLS_STALE_CONNECTION_THRESHOLD, 60, TimeUnit.SECONDS)
				.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, RETRANSMISSION_TIMEOUT_MS, TimeUnit.MILLISECONDS)
				.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, MAX_RETRANSMISSIONS)
				.set(DtlsConfig.DTLS_MAX_TRANSMISSION_UNIT, 1024)
				.setConnectionIdGenerator(clientCidGenerator)
				.setAdvancedCertificateVerifier(clientCertificateVerifier)
				.setHealthHandler(clientHealth);
		clientConnectionStore = ConnectorHelper.createDebugConnectionStore(clientConfigBuilder.build());
		clientHealth.reset();
		serverPskStore.setDelay(DtlsTestTools.DEFAULT_HANDSHAKE_RESULT_DELAY_MILLIS);
		serverCertificateProvider.setDelay(DtlsTestTools.DEFAULT_HANDSHAKE_RESULT_DELAY_MILLIS);
		serverCertificateVerifier.setDelay(DtlsTestTools.DEFAULT_HANDSHAKE_RESULT_DELAY_MILLIS);
		serverResumptionVerifier.setDelay(DtlsTestTools.DEFAULT_HANDSHAKE_RESULT_DELAY_MILLIS);
	}

	@After
	public void cleanUp() {
		timer.cancelAll();
		if (alternativeServerHelper != null && alternativeServerHelper.server != null) {
			alternativeServerHelper.server.stop();
			ConnectorHelper.assertReloadConnections("alt-server", alternativeServerHelper.server);
			alternativeServerHelper.destroyServer();
			alternativeServerHelper = null;
		}
		if (clientCertificateVerifier != null) {
			clientCertificateVerifier.shutdown();
			clientCertificateVerifier = null;
		}
		if (client != null) {
			client.stop();
			ConnectorHelper.assertReloadConnections("client", client);
			client.destroy();
			client = null;
		}
		lastReceivedFlight = null;
		if (serverHelper != null) {
			serverHelper.cleanUpServer();
		}
		TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(0L));
		TestConditionTools.assertStatisticCounter(serverHealth, "dropped sending records", is(0L));
		TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(0L));
		TestConditionTools.assertStatisticCounter(clientHealth, "dropped sending records", is(0L));
		clientHealth.reset();
		serverHealth.reset();
	}

	private void startClient() throws IOException {
		clientCertificateVerifier.setDelay(DtlsTestTools.DEFAULT_HANDSHAKE_RESULT_DELAY_MILLIS);
		serverPskStore.setDelay(0);
		serverCertificateProvider.setDelay(0);
		serverCertificateVerifier.setDelay(0);
		serverResumptionVerifier.setDelay(0);
		client = serverHelper.createClient(clientConfigBuilder.build(), clientConnectionStore);
		client.setExecutor(executor);
		client.start();
	}

	@Test
	public void testServerReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		clientConfigBuilder.set(DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES, false);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker with ReverseRecordLayer
			// to send message in bad order.
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null,
					new TestRecordLayer(rawClient, true), timer, createClientConnection(), clientConfigBuilder.build(),
					false);
			clientHandshaker.addSessionListener(sessionListener);
			// Start handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer (FINISHED, CHANGE CIPHER SPEC, ...,CERTIFICATE)
			processAll(clientHandshaker, rs);

			// Wait to receive response (should be CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle it
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("server", rawClient, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
		} finally {
			rawClient.stop();
		}
	}

	@Test
	public void testLimitedServerReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		alternativeServerHelper = new ConnectorHelper(network);
		alternativeServerHelper.serverBuilder
				.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, RETRANSMISSION_TIMEOUT_MS * 2, TimeUnit.MILLISECONDS)
				.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, MAX_RETRANSMISSIONS * 2)
				.set(DtlsConfig.DTLS_MAX_DEFERRED_INBOUND_RECORDS_SIZE, 96)
				.setHealthHandler(serverHealth)
				.setConnectionIdGenerator(serverCidGenerator);

		clientConfigBuilder
				.set(DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES, false)
				.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, MAX_RETRANSMISSIONS * 2);

		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer recordLayer = new TestRecordLayer(rawClient, true);
		try {
			// create limited server
			alternativeServerHelper.startServer();

			// Start connector
			rawClient.start();

			// Create handshaker with ReverseRecordLayer
			// to send message in bad order.
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(
					null, recordLayer, timer, createConnection(clientCidGenerator, alternativeServerHelper.serverEndpoint),
					clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);
			// Start handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(0L));

			// Handle and answer, reverse order (FINISHED, CHANGE CIPHER SPEC, ..., CERTIFICATE)
			processAll(clientHandshaker, rs);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(2L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			List<Record> records = collector.waitForRecords(500, TimeUnit.MILLISECONDS);
			assertThat("unexpected messages!", records, is(nullValue()));

			// retransmit reverse flight
			assertThat("scheduled jobs", timer.executeJobs(), is(1));

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(4L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			records = collector.waitForRecords(500, TimeUnit.MILLISECONDS);
			assertThat("unexpected messages!", records, is(nullValue()));

			// retransmit reverse flight again
			assertThat("scheduled jobs", timer.executeJobs(), is(1));
			// Wait to receive response (should be CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle it
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("server", rawClient, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(7L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);
		} finally {
			rawClient.stop();
			alternativeServerHelper.destroyServer();
			serverHealth.reset();
		}
	}

	@Test
	public void testClientReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer, true);
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1, 
					serverRecordLayer, timer, createServerConnection(), serverConfigSingleRecord);
			serverHandshaker.addSessionListener(sessionListener);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 3", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 3", collector, 1);
			// Handle and answer
			// (SERVER_HELLO, CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			processAll(serverHandshaker, rs);

			LatchSessionListener clientSessionListener = getSessionListenerForEndpoint("client", rawServer);

			// Wait for receive response (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 5", collector, 5);
			// Handle and answer (should be CCS, FINISHED, flight 6)
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			assertTrue("client handshake failed",
					clientSessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testServerResumeReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient, true);
		DtlsConnectorConfig clientConfig = clientConfigBuilder.set(DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES, false).build();
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					clientConnection, clientConfig, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Create resume handshaker
			sessionListener = new LatchSessionListener();
			DTLSSession session = new DTLSSession(clientHandshaker.getSession());
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(session,
					clientRecordLayer, timer, clientConnection, clientConfig, false);
			resumingClientHandshaker.addSessionListener(sessionListener);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, flight 2)
			rs = waitForFlightReceived("flight 2", collector, 3);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer ( CHANGE CIPHER SPEC, FINISHED, flight 3)
			processAll(resumingClientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertTrue("server handshake failed",
					serverSessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		} finally {
			rawClient.stop();
		}
	}

	@Test
	public void testClientResumeReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer, true);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1, serverRecordLayer, timer,
					createServerConnection(), serverConfigSingleRecord);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 1", collector, 1);

			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ...
			// SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(0L));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			serverHelper.serverConnectionStore.putEstablishedSession(serverHandshaker.getConnection());

			sessionListener = new LatchSessionListener();
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(1, 0, 
					serverRecordLayer, timer, createServerConnection(), serverConfigSingleRecord);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.ATTRIBUTE_HANDSHAKE_MODE_FORCE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED, flight 2).
			processAll(resumingServerHandshaker, rs);

			// Wait to receive response
			// (CCS, client FINISHED, flight 3) + (application data)
			List<Record> drops = waitForFlightReceived("flight 3 + app data", collector, 3);
			// remove application data, not retransmitted!
			drops.remove(2);

			// drop last flight 3, server resends flight 2
			assertThat("scheduled jobs", timer.executeJobs(), is(2));

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(2L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// Wait to receive response (CCS, client FINISHED, flight 3)
			// ("application data" doesn't belong to flight)
			rs = waitForFlightReceived("flight 3", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);
			processAll(resumingServerHandshaker, rs);

			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(2L));
		} finally {
			rawServer.stop();
			clientHealth.reset();
		}
	}

	@Test
	public void testClientProbesResume() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1, serverRecordLayer, timer,
					createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);
			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ...
			// SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			serverHelper.serverConnectionStore.putEstablishedSession(serverHandshaker.getConnection());

			sessionListener = new LatchSessionListener();
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(1, 0,
					serverRecordLayer, timer, createServerConnection(), serverHelper.serverConfig);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.ATTRIBUTE_HANDSHAKE_MODE_PROBE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED, flight 2).
			processAll(resumingServerHandshaker, rs);

			// Wait to receive response
			// (CCS, client FINISHED, flight 3) + (application data)
			List<Record> drops = waitForFlightReceived("flight 3 + app data", collector, 3);
			// remove application data, not retransmitted!
			drops.remove(2);

			// drop last flight 3, server resends flight 2
			assertThat("scheduled jobs", timer.executeJobs(), is(2));

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(2L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			// Wait to receive response (CCS, client FINISHED, flight 3)
			// ("application data" doesn't belong to flight)
			rs = waitForFlightReceived("flight 3", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);
			processAll(resumingServerHandshaker, rs);

			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(2L));

		} finally {
			rawServer.stop();
			clientHealth.reset();
		}
	}

	@Test
	public void testClientProbesFull() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);

		DtlsConnectorConfig serverConfig = DtlsConnectorConfig.builder(serverHelper.serverConfig)
			.set(DtlsConfig.DTLS_SERVER_USE_SESSION_ID, false)
			.build();

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1, serverRecordLayer, timer,
					createServerConnection(), serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 1", collector, 1);

			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ... SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			ServerHandshaker resumingServerHandshaker = new ServerHandshaker(1, 1,
					serverRecordLayer, timer, createServerConnection(), serverConfig);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.ATTRIBUTE_HANDSHAKE_MODE_PROBE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 1", collector, 1);

			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ... SERVER HELLO DONE)
			processAll(resumingServerHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3 + app data", collector, 5);
			processAll(resumingServerHandshaker, rs);

			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testClientProbesResumeReceivingMessagesInBadOrderDuringHandshake() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer, true);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1, serverRecordLayer, timer,
					createServerConnection(), serverConfigSingleRecord);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ...
			// SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(0L));

			serverHelper.serverConnectionStore.putEstablishedSession(serverHandshaker.getConnection());

			sessionListener = new LatchSessionListener();
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(1, 0,
					serverRecordLayer, timer, createServerConnection(), serverConfigSingleRecord);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.ATTRIBUTE_HANDSHAKE_MODE_PROBE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED, flight 2).
			processAll(resumingServerHandshaker, rs);

			List<Record> records = collector.waitForRecords(500, TimeUnit.MILLISECONDS);
			assertThat("unexpected messages!", records, is(nullValue()));

			// FINISH dropped
			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// probing would drop the FINISH epoch 1, therefore resend flight
			assertThat("scheduled jobs", timer.executeJobs(), is(2));

			// Wait to receive response
			// (CCS, client FINISHED, flight 3) + (application data)
			List<Record> drops = waitForFlightReceived("flight 3 + app data", collector, 3);
			// remove application data, not retransmitted!
			drops.remove(2);

			// retransmission dropped SERVER_HELLO and CCS
			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(3L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// drop last flight 3, server resends flight 2
			assertThat("scheduled jobs", timer.executeJobs(), is(1));


			// Wait to receive response (CCS, client FINISHED, flight 3)
			// ("application data" doesn't belong to flight)
			rs = waitForFlightReceived("flight 3", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);
			processAll(resumingServerHandshaker, rs);

			// retransmission drops SERVER_HELLO and CCS again
			// but FINISH is processed to trigger retransmission of last server flight
			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(5L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

		} finally {
			rawServer.stop();
			clientHealth.reset();
		}
	}

	@Test
	public void testClientProbesResumeTimeout() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1, serverRecordLayer, timer,
					createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ...
			// SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(1, 0,
					serverRecordLayer, timer, createServerConnection(), serverHelper.serverConfig);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.ATTRIBUTE_HANDSHAKE_MODE_PROBE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// drop it
			// Wait to re-receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1 (retransmit 1)", collector, 1);
			// drop it
			// Wait to re-receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1 (retransmit 2)", collector, 1);
			// drop it

			assertSessionState("client", rawServer, SessionState.FAILED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// probe handshake failed without receiving data
			context = new AddressEndpointContext(rawServer.getAddress());
			data = RawData.outbound("Hello World, next again!".getBytes(), context, null, false);
			client.send(data);

			rs = waitForFlightReceived("app data", collector, 1);
			Record record = rs.get(0);
			assertThat(record.getEpoch(), is(1));
			assertThat(record.getType(), anyOf(is(ContentType.APPLICATION_DATA), is(ContentType.TLS12_CID)));

		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testClientProbesFullTimeout() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);

		DtlsConnectorConfig serverConfig = DtlsConnectorConfig.builder(serverHelper.serverConfig)
				.set(DtlsConfig.DTLS_SERVER_USE_SESSION_ID, false)
				.build();

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1, serverRecordLayer, timer,
					createServerConnection(), serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer (should be SERVER_HELLO, CERTIFICATE, ... SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			sessionListener = new LatchSessionListener();
			ServerHandshaker resumingServerHandshaker = new ServerHandshaker(1, 1,
					serverRecordLayer, timer, createServerConnection(), serverConfig);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.ATTRIBUTE_HANDSHAKE_MODE_PROBE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// drop it
			// Wait to re-receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1 (retransmit 1)", collector, 1);
			// drop it
			// Wait to re-receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1 (retransmit 2)", collector, 1);
			// drop it
			assertSessionState("client", rawServer, SessionState.FAILED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// probe handshake failed without receiving data
			context = new AddressEndpointContext(rawServer.getAddress());
			data = RawData.outbound("Hello World, next again!".getBytes(), context, null, false);
			client.send(data);

			rs = waitForFlightReceived("app data", collector, 1);
			Record record = rs.get(0);
			assertThat(record.getEpoch(), is(1));
			assertThat(record.getType(), anyOf(is(ContentType.APPLICATION_DATA), is(ContentType.TLS12_CID)));
		} finally {
			rawServer.stop();
			clientHealth.reset();
		}
	}

	/**
	 * Test retransmission of last flight.
	 * 
	 * RFC6347, section 4.2.4, fig. 2
	 * 
	 * "testFinishedMessageRetransmission" drops the first transmission of
	 * flight 5 to test, if flight 5 is retransmitted. But flight 5 is just
	 * usual retransmission, the special case is flight 6. Therefore this test
	 * drops the 1. transmission of flight 6 to check, if retransmission of
	 * flight 5 triggers the retransmission of flight 6.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerFinishedMessageRetransmission() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null,
					clientRecordLayer, timer, createClientConnection(), clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start handshake (Send CLIENT HELLO, flight 1)
			clientHandshaker.startHandshake();

			// Wait to receive response
			// (HELLO VERIFY REQUEST, flight 2)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie, flight 3)
			processAll(clientHandshaker, rs);

			// Wait for response
			// (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE, flight 4)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED, flight 5)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			List<Record> drops = waitForFlightReceived("flight 6", collector, 2);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(0L));

			// Ignore the receive response, client resends flight 5
			assertThat("scheduled jobs", timer.executeJobs(), is(1));

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(4L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			// Wait for retransmission
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			rs = waitForFlightReceived("flight 6", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("server", rawClient, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(4L));
		} finally {
			rawClient.stop();
			serverHealth.reset();
		}
	}

	/**
	 * Test back-off retransmission of flight.
	 * 
	 * RFC6347, section 4.1.1.1, page 12
	 * 
	 * "If repeated retransmissions do not result in a response, and the
	 * PMTU is unknown, subsequent retransmissions SHOULD back off to a
	 * smaller record size, fragmenting the handshake message as
	 * appropriate. This standard does not specify an exact number of
	 * retransmits to attempt before backing off, but 2-3 seems
	 * appropriate."
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testClientBackOffRetransmission() throws Exception {
		alternativeServerHelper = new ConnectorHelper(network);

		alternativeServerHelper.serverBuilder
				.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, RETRANSMISSION_TIMEOUT_MS * 2, TimeUnit.MILLISECONDS)
				.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, MAX_RETRANSMISSIONS * 2)
				.set(DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES, false)
				.setHealthHandler(serverHealth)
				.setConnectionIdGenerator(serverCidGenerator);

		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);

		try {
			// create limited server
			alternativeServerHelper.startServer();

			// Start connector
			rawClient.start();

			// Create handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null,
					clientRecordLayer, timer, createConnection(clientCidGenerator, alternativeServerHelper.serverEndpoint), clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start handshake (Send CLIENT HELLO, flight 1)
			clientHandshaker.startHandshake();

			// Wait to receive response
			// (HELLO VERIFY REQUEST, flight 2)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie, flight 3)
			processAll(clientHandshaker, rs);

			// Wait for response
			// (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE, flight 4)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED, flight 5)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			List<Record> drops = waitForFlightReceived("flight 6", collector, 2);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(0L));

			// Ignore the receive response, client resends flight 5
			assertThat("scheduled jobs", timer.executeJobs(), is(1));

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(4L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			// Wait for retransmission
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			rs = waitForFlightReceived("flight 6", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);

			assertThat(clientRecordLayer.getLastSentDatagrams(), is(1));

			// Ignore the receive response, client resends flight 5
			assertThat("scheduled jobs", timer.executeJobs(), is(1));

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(8L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			// Wait for retransmission
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			rs = waitForFlightReceived("flight 6", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);

			assertThat(clientRecordLayer.getLastSentDatagrams(), is(4));

			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("server", rawClient, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(8L));
		} finally {
			rawClient.stop();
			alternativeServerHelper.destroyServer();
			serverHealth.reset();
		}
	}

	/**
	 * Test back-off retransmission of server flight 4.
	 * 
	 * RFC6347, section 4.1.1.1, page 12
	 * 
	 * "If repeated retransmissions do not result in a response, and the
	 * PMTU is unknown, subsequent retransmissions SHOULD back off to a
	 * smaller record size, fragmenting the handshake message as
	 * appropriate. This standard does not specify an exact number of
	 * retransmits to attempt before backing off, but 2-3 seems
	 * appropriate."
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerBackOffRetransmission() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1,
					serverRecordLayer, timer, createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 1", collector, 1);

			// Handle and answer
			// (SERVER_HELLO, CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			processAll(serverHandshaker, rs);

			// Ignore transmission (CERTIFICATE, ... , FINISHED, flight 5)
			List<Record> drops = waitForFlightReceived("flight 3", collector, 5);
			// server retransmission

			assertThat(serverRecordLayer.getLastSentDatagrams(), is(1));

			assertThat("scheduled jobs", timer.executeJobs(), is(1));

			// Wait for retransmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);
			assertFlightRecordsRetransmitted(drops, rs);

			assertThat(serverRecordLayer.getLastSentDatagrams(), is(1));

			assertThat("scheduled jobs", timer.executeJobs(), is(1));
			
			// Wait for retransmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);
			assertFlightRecordsRetransmitted(drops, rs);

			assertThat(serverRecordLayer.getLastSentDatagrams(), is(5));

			// Handle and answer (should be CCS, FINISHED, flight 6)
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
		} finally {
			rawServer.stop();
		}
	}

	/**
	 * Test processing close notify after session is established, but not
	 * completed.
	 */
	@Test
	public void testServerCloseAfterFinishedMessage() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null,
					clientRecordLayer, timer, clientConnection, clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start handshake (Send CLIENT HELLO, flight 1)
			clientHandshaker.startHandshake();

			// Wait to receive response
			// (HELLO VERIFY REQUEST, flight 2)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie, flight 3)
			processAll(clientHandshaker, rs);

			// Wait for response
			// (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE, flight 4)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED, flight 5)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			rs = waitForFlightReceived("flight 6", collector, 2);
			processAll(clientHandshaker, rs);

			timer.executeJobs();
			serverHealth.reset();

			TestConditionTools.assertStatisticCounter(serverHealth, "handshakes succeeded", is(0L));

			AlertMessage close = new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
			send(clientConnection, clientRecordLayer, close);
			// Wait to receive response from server
			// (CLOSE_NOTIFY, flight 8)
			rs = waitForFlightReceived("flight 8", collector, 1);

			// send close again
			send(clientConnection, clientRecordLayer, close);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(serverHealth, "handshakes succeeded", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		} finally {
			rawClient.stop();
			serverHealth.reset();
		}
	}

	/**
	 * Test processing close notify after session is established, but not
	 * completed.
	 */
	@Test
	public void testServerDecodesAfterUnorderedClose() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null,
					clientRecordLayer, timer, clientConnection, clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start handshake (Send CLIENT HELLO, flight 1)
			clientHandshaker.startHandshake();

			// Wait to receive response
			// (HELLO VERIFY REQUEST, flight 2)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie, flight 3)
			processAll(clientHandshaker, rs);

			// Wait for response
			// (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE, flight 4)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED, flight 5)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			rs = waitForFlightReceived("flight 6", collector, 2);
			processAll(clientHandshaker, rs);

			serverHealth.reset();

			ApplicationMessage app = new ApplicationMessage("hi".getBytes());
			send(clientConnection, clientRecordLayer, app);

			// app response
			rs = waitForFlightReceived("response", collector, 1);

			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			TestConditionTools.assertStatisticCounter(serverHealth, "sending records", is(1L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);
			TestConditionTools.assertStatisticCounter(serverHealth, "handshakes succeeded", is(1L));
			TestConditionTools.assertStatisticCounter(serverHealth, "handshakes failed", is(0L));
			TestConditionTools.assertStatisticCounter(serverHealth, "dropped sending records", is(0L));
			TestConditionTools.assertStatisticCounter(serverHealth, "received records", is(1L));
			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(0L));

			serverHealth.reset();

			app = new ApplicationMessage("hi, again".getBytes());
			AlertMessage close = new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);

			clientRecordLayer.setReverse(true);
			send(clientConnection, clientRecordLayer, app, close);

			// (CLOSE_NOTIFY)
			rs = waitForFlightReceived("close", collector, 1);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped sending records", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			TestConditionTools.assertStatisticCounter(serverHealth, "sending records", is(2L));
			TestConditionTools.assertStatisticCounter(serverHealth, "received records", is(2L));
			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(0L));

			app = new ApplicationMessage("bye".getBytes());
			send(clientConnection, clientRecordLayer, app);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			TestConditionTools.assertStatisticCounter(serverHealth, "received records", is(3L));

		} finally {
			rawClient.stop();
			serverHealth.reset();
		}
	}

	/**
	 * Test processing reordered application records using a newer record filter.
	 */
	@Test
	public void testServerWithNewerFilterDropsOlderRecords() throws Exception {
		alternativeServerHelper = new ConnectorHelper(network);

		alternativeServerHelper.serverBuilder
				.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, RETRANSMISSION_TIMEOUT_MS * 2, TimeUnit.MILLISECONDS)
				.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, MAX_RETRANSMISSIONS * 2)
				.set(DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES, false)
				.set(DtlsConfig.DTLS_USE_NEWER_RECORD_FILTER, true)
				.setHealthHandler(serverHealth)
				.setConnectionIdGenerator(serverCidGenerator);

		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {
			// create limited server
			alternativeServerHelper.startServer();

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createConnection(clientCidGenerator, alternativeServerHelper.serverEndpoint);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null,
					clientRecordLayer, timer, clientConnection, clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start handshake (Send CLIENT HELLO, flight 1)
			clientHandshaker.startHandshake();

			// Wait to receive response
			// (HELLO VERIFY REQUEST, flight 2)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie, flight 3)
			processAll(clientHandshaker, rs);

			// Wait for response
			// (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE, flight 4)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED, flight 5)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED, flight 6)
			rs = waitForFlightReceived("flight 6", collector, 2);
			processAll(clientHandshaker, rs);

			serverHealth.reset();

			ApplicationMessage app = new ApplicationMessage("hi".getBytes());
			send(clientConnection, clientRecordLayer, app);

			// app response
			rs = waitForFlightReceived("response", collector, 1);

			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			TestConditionTools.assertStatisticCounter(serverHealth, "sending records", is(1L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);
			TestConditionTools.assertStatisticCounter(serverHealth, "handshakes succeeded", is(1L));
			TestConditionTools.assertStatisticCounter(serverHealth, "handshakes failed", is(0L));
			TestConditionTools.assertStatisticCounter(serverHealth, "dropped sending records", is(0L));
			TestConditionTools.assertStatisticCounter(serverHealth, "received records", is(1L));
			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(0L));

			serverHealth.reset();

			ApplicationMessage app1 = new ApplicationMessage("hi, too late".getBytes());
			ApplicationMessage app2 = new ApplicationMessage("hi, again".getBytes());

			clientRecordLayer.setReverse(true);
			send(clientConnection, clientRecordLayer, app1, app2);

			// response for app2
			rs = waitForFlightReceived("response", collector, 1);

			TestConditionTools.assertStatisticCounter(serverHealth, "dropped received records", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			TestConditionTools.assertStatisticCounter(serverHealth, "received records", is(2L));
			TestConditionTools.assertStatisticCounter(serverHealth, "sending records", is(1L));

		} finally {
			rawClient.stop();
			alternativeServerHelper.destroyServer();
			serverHealth.reset();
		}
	}

	/**
	 * Test retransmission of last flight of resuming handshake.
	 * 
	 * RFC6347, section 4.2.4, fig. 2
	 * 
	 * "testResumeFinishedMessageRetransmission" drops the first transmission of
	 * flight 2 to test, if flight 2 is retransmitted. But flight 2 is just
	 * usual retransmission, the special case is flight 3. Therefore this test
	 * drops the 1. transmission of flight 3 to check, if retransmission of
	 * flight 2 triggers the retransmission of flight 3.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testResumeClientFinishedMessageRetransmission() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1, serverRecordLayer, timer,
					createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 3", collector, 1);
			// Handle and answer (should be CERTIFICATE, ... SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			serverHelper.serverConnectionStore.putEstablishedSession(serverHandshaker.getConnection());

			sessionListener = new LatchSessionListener();
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(1, 0,
					serverRecordLayer, timer, createServerConnection(), serverHelper.serverConfig);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.ATTRIBUTE_HANDSHAKE_MODE_FORCE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED, VERIFY REQUEST, flight 2).
			processAll(resumingServerHandshaker, rs);

			// Wait to receive response
			// (CCS, client FINISHED, flight 3) + (application data)
			List<Record> drops = waitForFlightReceived("flight 3", collector, 3);
			// remove application data, not retransmitted!
			drops.remove(2);

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(0L));

			// drop last flight 3, server resends flight 2
			assertThat("scheduled jobs", timer.executeJobs(), is(2));

			// Wait to receive response (CCS, client FINISHED, flight 3)
			// ("application data" doesn't belong to flight)
			rs = waitForFlightReceived("flight 3", collector, 2);
			assertFlightRecordsRetransmitted(drops, rs);
			processAll(resumingServerHandshaker, rs);
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(2L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

		} finally {
			rawServer.stop();
			clientHealth.reset();
		}
	}

	@Test
	public void testResumeClientCloseAfterFinishedMessage() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1, serverRecordLayer, timer,
					createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 1", collector, 1);

			// Handle and answer (should be CERTIFICATE, ... SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			serverHelper.serverConnectionStore.putEstablishedSession(serverHandshaker.getConnection());

			sessionListener = new LatchSessionListener();
			Connection serverConnection = createServerConnection();
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(0, 0,
					serverRecordLayer, timer, serverConnection, serverHelper.serverConfig);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.ATTRIBUTE_HANDSHAKE_MODE_FORCE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED, flight 2).
			processAll(resumingServerHandshaker, rs);

			// Wait to receive response
			// (CCS, client FINISHED, flight 3) + (application data)
			rs = waitForFlightReceived("flight 3", collector, 3);
			// remove application data,
			// prevent resuming client handshaker from completion
			rs.remove(2);
			processAll(resumingServerHandshaker, rs);

			clientHealth.reset();

			AlertMessage close = new AlertMessage(AlertLevel.WARNING, AlertDescription.CLOSE_NOTIFY);
			send(serverConnection, serverRecordLayer, close);

			// Wait to receive response from server
			// (CLOSE_NOTIFY, flight 5)
			rs = waitForFlightReceived("flight 5", collector, 1);

			send(serverConnection, serverRecordLayer, close);

			TestConditionTools.assertStatisticCounter(clientHealth, "dropped received records", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			TestConditionTools.assertStatisticCounter(clientHealth, "handshakes succeeded", is(1L),
					MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

		} finally {
			rawServer.stop();
			clientHealth.reset();
		}
	}

	/**
	 * Test retransmission of flight before last flight.
	 * 
	 * RFC6347, section 4.2.4, fig. 2
	 * 
	 * Drops the first transmission of flight 5 to test, if flight 5 is
	 * retransmitted. Usual retransmission, the special case is flight 6, see
	 * "testServerFinishedMessageRetransmission".
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testFinishedMessageRetransmission() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1,
					serverRecordLayer, timer, createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 1", collector, 1);

			// Handle and answer
			// (CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			processAll(serverHandshaker, rs);

			// Ignore transmission (CERTIFICATE, ... , FINISHED, flight 5)
			List<Record> drops = waitForFlightReceived("flight 3", collector, 5);

			// Wait for retransmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);
			assertFlightRecordsRetransmitted(drops, rs);
			// Handle and answer (should be CCS, FINISHED, flight 6)
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("client", rawServer, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

		} finally {
			rawServer.stop();
		}
	}

	/**
	 * Test retransmission of flight before last flight of resuming handshake.
	 * 
	 * RFC6347, section 4.2.4, fig. 2
	 * 
	 * Drops the first transmission of flight 2 to test, if flight 2 is
	 * retransmitted. Flight 2 is just usual retransmission, the special case is
	 * flight 3, see "testResumeClientFinishedMessageRetransmission". Note:
	 * scandium uses a additional HELLO VERIFY REQUEST. May be optimized in the
	 * future.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testResumeFinishedMessageRetransmission() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					clientConnection, clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Create resume handshaker
			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientHandshaker.getSession());
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					clientRecordLayer, timer, clientConnection, clientConfigBuilder.build(), false);
			resumingClientHandshaker.addSessionListener(sessionListener);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 2)
			List<Record> drops = waitForFlightReceived("flight 2", collector, 3);

			// drop it, force retransmission
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 2)
			rs = waitForFlightReceived("flight 2", collector, 3);
			assertFlightRecordsRetransmitted(drops, rs);
			// Handle and answer ( CHANGE CIPHER SPEC, FINISHED, flight 3)
			processAll(resumingClientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("server", rawClient, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server resuming handshake fails, if clients FINISH is dropped.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerResumeTimeout() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		DtlsConnectorConfig clientConfig = clientConfigBuilder.set(DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES, false).build();
		try {
			int remain = serverHelper.serverConnectionStore.remainingCapacity();

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					clientConnection, clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Ensure server side connection expects cid
			Connection serverSideConnection = serverHelper.serverConnectionStore.get(rawClient.getAddress());
			assertNotNull(serverSideConnection);
			boolean expectedCid = ConnectionId.useConnectionId(serverCidGenerator) && ConnectionId.supportsConnectionId(clientCidGenerator);
			assertThat(serverSideConnection.expectCid(), is(expectedCid));

			if (serverHelper.serverSessionStore == null || expectedCid) {
				// with cid, the connection is still accessible and therefore not removed.
				// without session store, a session-connection map is used and so the
				// connection is still accessible and therefore not removed.
				remain = serverHelper.serverConnectionStore.remainingCapacity();
			}

			// Create resume handshaker
			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientHandshaker.getSession());
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					clientRecordLayer, timer, clientConnection, clientConfig, false);
			resumingClientHandshaker.addSessionListener(sessionListener);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 2)
			rs = waitForFlightReceived("flight 2", collector, 3);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer
			// (CHANGE CIPHER SPEC, FINISHED (drop), flight 3)
			clientRecordLayer.setDrop(-1);
			processAll(resumingClientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 1));
			Throwable error = serverSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("server handshake not failed", error);
			assertThat(error, instanceOf(DtlsHandshakeTimeoutException.class));
			assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server handshake fails, if clients FINISH is dropped.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerTimeout() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		DtlsConnectorConfig clientConfig = clientConfigBuilder.set(DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES, false).build();
		int remain = serverHelper.serverConnectionStore.remainingCapacity();
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					createClientConnection(), clientConfig, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			clientRecordLayer.setDrop(-1);
			processAll(clientHandshaker, rs);

			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			Throwable error = serverSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("server handshake not failed", error);
			assertThat(error, instanceOf(DtlsHandshakeTimeoutException.class));
			assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawClient.stop();
		}
	}

	@Test
	public void testClientResumeTimeout() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);
		TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);
		int remain = clientConnectionStore.remainingCapacity();

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1, serverRecordLayer, timer,
					createServerConnection(), serverHelper.serverConfig);
			serverHandshaker.addSessionListener(sessionListener);

			// 1. handshake
			// Wait to receive response (should be CLIENT HELLO)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 3", collector, 1);
			// Handle and answer (should be CERTIFICATE, ... SERVER HELLO DONE)
			processAll(serverHandshaker, rs);

			// Wait to receive response (CERTIFICATE, ... , FINISHED)
			rs = waitForFlightReceived("flight 3", collector, 5);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// application data
			rs = waitForFlightReceived("app data", collector, 1);

			// Ensure server side connection expects cid
			Connection clientSideConnection = clientConnectionStore.get(rawServer.getAddress());
			assertNotNull(clientSideConnection);
			boolean expectedCid = ConnectionId.useConnectionId(clientCidGenerator) && ConnectionId.supportsConnectionId(serverCidGenerator);
			assertThat(clientSideConnection.expectCid(), is(expectedCid));

			sessionListener = new LatchSessionListener();
			ResumingServerHandshaker resumingServerHandshaker = new ResumingServerHandshaker(1, 0,
					serverRecordLayer, timer, createServerConnection(), serverConfigSingleRecord);
			resumingServerHandshaker.addSessionListener(sessionListener);

			// force resuming handshake
			EndpointContext context = new MapBasedEndpointContext(rawServer.getAddress(), null,
					DtlsEndpointContext.ATTRIBUTE_HANDSHAKE_MODE_FORCE);
			data = RawData.outbound("Hello World, Again!".getBytes(), context, null, false);
			client.send(data);

			// Wait to receive response (should be CLIENT HELLO, flight 1)
			rs = waitForFlightReceived("flight 1", collector, 1);

			LatchSessionListener clientSessionListener = getSessionListenerForEndpoint("client", rawServer);

			// Handle and answer
			// (SERVER HELLO, CCS, FINISHED drop, flight 2).
			serverRecordLayer.setDrop(-1);
			processAll(resumingServerHandshaker, rs);

			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			Throwable error = clientSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("client handshake not failed", error);
			assertThat(error, instanceOf(DtlsHandshakeTimeoutException.class));
			assertThat(clientConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testClientTimeout() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);
		int remain = clientConnectionStore.remainingCapacity();

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1,
					serverRecordLayer, timer, createServerConnection(), serverConfigSingleRecord);
			serverHandshaker.addSessionListener(sessionListener);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 3", collector, 1);
			// Handle and answer
			// (CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			processAll(serverHandshaker, rs);

			LatchSessionListener clientSessionListener = getSessionListenerForEndpoint("client", rawServer);

			// Wait for transmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);
			// Handle and answer (should be CCS, FINISHED (drop), flight 6)
			serverRecordLayer.setDrop(-1);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			Throwable error = clientSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("client handshake not failed", error);
			assertThat(error, instanceOf(DtlsHandshakeTimeoutException.class));
			assertThat(clientConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testClientExpires() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);
		int remain = clientConnectionStore.remainingCapacity();
		int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1,
					serverRecordLayer, timer, createServerConnection(), serverConfigSingleRecord);
			serverHandshaker.addSessionListener(sessionListener);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 3", collector, 1);
			// Handle and answer
			// (CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			processAll(serverHandshaker, rs);

			LatchSessionListener clientSessionListener = getSessionListenerForEndpoint("client", rawServer);

			// Wait for transmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);

			clientHealth.reset();

			// Handle and answer (should be CCS, FINISHED (drop), flight 6)
			serverRecordLayer.setDrop(-1);
			processAll(serverHandshaker, rs);

			TestConditionTools.assertStatisticCounter(clientHealth, "received records", is(1L), MAX_TIME_TO_WAIT_SECS,
					TimeUnit.SECONDS);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// the CCS must be processed before the time shift ... otherwise it may get discarded
			Thread.sleep(500);
			time.addTestTimeShift(timeout * 2, TimeUnit.MILLISECONDS);

			// Ensure handshake failed before retransmissions timeout
			Throwable error = clientSessionListener.waitForSessionFailed(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("client handshake not failed", error);
			assertTrue(error.getMessage(), error.getMessage().contains("expired"));
			assertThat(clientConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testResumeWithHelloVerifyRequest() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);

		RecordCollectorDataHandler alt1Collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawAlt1Client = new UdpConnector(LOCAL, alt1Collector);

		RecordCollectorDataHandler alt2Collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawAlt2Client = new UdpConnector(LOCAL, alt2Collector);

		try {
			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, new TestRecordLayer(rawClient),
					timer, clientConnection, clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Create 1. resume handshaker
			rawAlt1Client.start();
			LatchSessionListener alt1SessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientHandshaker.getSession());
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					new TestRecordLayer(rawAlt1Client), timer, clientConnection, clientConfigBuilder.build(), false);
			resumingClientHandshaker.addSessionListener(alt1SessionListener);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 4)
			rs = waitForFlightReceived("flight 4", alt1Collector, 3);

			// Create 2. resume handshaker
			rawAlt2Client.start();
			LatchSessionListener alt2SessionListener = new LatchSessionListener();
			resumableSession = new DTLSSession(clientHandshaker.getSession());
			resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					new TestRecordLayer(rawAlt2Client), timer, clientConnection, clientConfigBuilder.build(), false);
			resumingClientHandshaker.addSessionListener(alt2SessionListener);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (HELLO_VERIFY_REQUEST, fight 2)
			rs = waitForFlightReceived("flight 2", alt2Collector, 1);

			// Send CLIENT HELLO with cookie, flight 3
			processAll(resumingClientHandshaker, rs);

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, fight 4)
			rs = waitForFlightReceived("flight 4", alt2Collector, 3);

			// create server session listener to ensure,
			// that server finish also the handshake
			serverHelper.serverConnectionStore.dump();

			processAll(resumingClientHandshaker, rs);

			assertTrue("client 2. resumed handshake failed",
					alt2SessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			assertSessionState("server", rawAlt2Client, SessionState.ESTABLISHED, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);

			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			assertSessionState("server", rawAlt1Client, SessionState.FAILED, timeout, TimeUnit.MILLISECONDS);

		} finally {
			rawClient.stop();
			rawAlt1Client.stop();
			rawAlt2Client.stop();
		}
	}

	@Test
	public void testServerNoCCS() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		DtlsConnectorConfig clientConfig = clientConfigBuilder.set(DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES, false).build();
		int remain = serverHelper.serverConnectionStore.remainingCapacity();
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					createClientConnection(), clientConfig, false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);

			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			clientRecordLayer.setDrop(-2); // drop CCS
			processAll(clientHandshaker, rs);

			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));

			assertSessionState("server", rawClient, SessionState.FAILED, timeout, TimeUnit.MILLISECONDS);

			assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawClient.stop();
		}
	}

	@Test
	public void testClientNoCCS() throws Exception {
		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);
		int remain = clientConnectionStore.remainingCapacity();

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1,
					serverRecordLayer, timer, createServerConnection(), serverConfigSingleRecord);
			serverHandshaker.addSessionListener(sessionListener);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 1", collector, 1);
			// Handle and answer
			// (CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			processAll(serverHandshaker, rs);

			// Wait for transmission (CERTIFICATE, ... , FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 5);
			// Handle and answer (should be CCS (drop), FINISHED, flight 6)
			serverRecordLayer.setDrop(-2);
			processAll(serverHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("server handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			assertSessionState("client", rawServer, SessionState.FAILED, timeout, TimeUnit.MILLISECONDS);
			assertThat(clientConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawServer.stop();
		}
	}

	@Test
	public void testServerAdverseryClient() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		int remain = serverHelper.serverConnectionStore.remainingCapacity();
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			DTLSSession clientSession = new DTLSSession();
			LatchSessionListener sessionListener = new LatchSessionListener();
			AdversaryClientHandshaker clientHandshaker = new AdversaryClientHandshaker(clientSession, clientRecordLayer,
					timer, createClientConnection(), clientConfigBuilder.build());
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer
			// (CERTIFICATE, (NO CHANGE CIPHER SPEC), ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			Throwable error = serverSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);

			if (error == null) {

				rs = waitForFlightReceived("flight 5", collector, 2);
				processAll(clientHandshaker, rs);

				clientHandshaker.sendApplicationData("Hello".getBytes());

				rs = waitForFlightReceived("flight 6 (app data)", collector, 1);
				for (Record data : rs) {
					data.decodeFragment(clientHandshaker.getDtlsContext().getReadState());
					System.out.println(data);
					DTLSMessage message = data.getFragment();
					byte[] array = message.toByteArray();
					System.out.println(StringUtil.byteArray2Hex(array) + " / " + new String(array));
				}

				RawData message = serverHelper.serverRawDataProcessor.getLatestInboundMessage();
				System.out
						.println(StringUtil.byteArray2Hex(message.getBytes()) + " / " + new String(message.getBytes()));
			}
			assertNotNull("server handshake not failed", error);
			assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server handshake fails, if the PSK secret result is not received
	 * in time.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerPskTimeout() throws Exception {
		// Configure and create UDP connector
		pskHandshakeResponses = 0; // no psk response

		clientConfigBuilder
				.setAdvancedPskStore(new AdvancedSinglePskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()))
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		int remain = serverHelper.serverConnectionStore.remainingCapacity();
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					createClientConnection(), clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, SERVER_KEY_EXCHANGE, SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 3);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer
			// (CLIENT_KEY_EXCHANGE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			waitForAlertReceived("timeout", collector);

			Throwable error = serverSessionListener.waitForSessionFailed(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("server handshake not failed", error);
			assertThat(error, instanceOf(HandshakeException.class));
			assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server handshake succeeds, if the PSK secret result is received
	 * twice.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerPskDoubleResponse() throws Exception {
		// Configure and create UDP connector
		pskHandshakeResponses = 2; // two psk responses
		
		clientConfigBuilder
				.setAdvancedPskStore(new AdvancedSinglePskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()))
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					createClientConnection(), clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, SERVER_KEY_EXCHANGE, SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 3);

			// Handle and answer
			// (CLIENT_KEY_EXCHANGE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake succeeded
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			assertSessionState("server", rawClient, SessionState.ESTABLISHED, timeout, TimeUnit.MILLISECONDS);
		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server handshake fails, if the x509 verification result is not received
	 * in time.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerx509Timeout() throws Exception {
		// Configure and create UDP connector
		verifyHandshakeResponses = 0; // no x509 verification response

		clientConfigBuilder
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientCertificateChain()))
				.setAdvancedCertificateVerifier(StaticNewAdvancedCertificateVerifier.builder().setTrustedCertificates(DtlsTestTools.getTrustedCertificates()).build());

		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		int remain = serverHelper.serverConnectionStore.remainingCapacity();
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					createClientConnection(), clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE (2 fragments), SERVER_KEY_EXCHANGE,
			// CERTIFICATE REQUEST, SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 6);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer
			// (CLIENT_KEY_EXCHANGE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			waitForAlertReceived("timeout", collector);

			Throwable error = serverSessionListener.waitForSessionFailed(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("server handshake not failed", error);
			assertThat(error, instanceOf(HandshakeException.class));
			assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server handshake succeeds, if the x509 verification result is received
	 * twice.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerx509DoubleResponse() throws Exception {
		logging.setLoggingLevel("ERROR", DTLSConnector.class);
		// Configure and create UDP connector
		verifyHandshakeResponses = 2; // two x509 verification responses

		clientConfigBuilder
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientCertificateChain()))
				.setAdvancedCertificateVerifier(StaticNewAdvancedCertificateVerifier.builder().setTrustedCertificates(DtlsTestTools.getTrustedCertificates()).build());

		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					createClientConnection(), clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE (2 fragments), SERVER_KEY_EXCHANGE,
			// CERTIFICATE REQUEST, SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 6);

			// Handle and answer
			// (CLIENT_KEY_EXCHANGE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake succeeded
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			assertSessionState("server", rawClient, SessionState.ESTABLISHED, timeout, TimeUnit.MILLISECONDS);
		} finally {
			rawClient.stop();
		}
	}

	@Test
	public void testClientX509WithoutMatchingCertificate() throws Exception {
		logging.setLoggingLevel("OFF", LOGGER.getName());

		NewAdvancedCertificateVerifier verifier = StaticNewAdvancedCertificateVerifier.builder()
				.setTrustedCertificates(DtlsTestTools.getServerCaRsaCertificateChain()).build();

		DtlsConnectorConfig.Builder serverBuilder = DtlsConnectorConfig.builder(serverHelper.serverConfig)
				.set(DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES, false)
				.setAdvancedCertificateVerifier(verifier)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain(), CertificateType.X_509));

		// Configure UDP connector we will use as Server
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(serverCidGenerator);
		UdpConnector rawServer = new UdpConnector(LOCAL, collector);
		int remain = clientConnectionStore.remainingCapacity();

		try {
			// Start connector (Server)
			rawServer.start();

			// Start the client
			startClient();

			RawData data = RawData.outbound("Hello World".getBytes(),
					new AddressEndpointContext(rawServer.getAddress()), null, false);
			client.send(data);

			// Create server handshaker
			TestRecordLayer serverRecordLayer = new TestRecordLayer(rawServer);
			LatchSessionListener sessionListener = new LatchSessionListener();
			ServerHandshaker serverHandshaker = new ServerHandshaker(1, 1,
					serverRecordLayer, timer, createServerConnection(), serverBuilder.build());
			serverHandshaker.addSessionListener(sessionListener);

			// Wait to receive response (should be CLIENT HELLO, flight 3)
			List<Record> rs = waitForFlightReceived("flight 1", collector, 1);

			sendHelloVerifyRequest(serverRecordLayer, rs);

			// Wait to receive response (should be CLIENT HELLO with cookie)
			rs = waitForFlightReceived("flight 1", collector, 1);

			// Handle and answer
			// (CERTIFICATE, ... SERVER HELLO DONE, flight 4)
			processAll(serverHandshaker, rs);

			LatchSessionListener clientSessionListener = getSessionListenerForEndpoint("client", rawServer);

			// Wait for transmission (CERTIFICATE (empty), CLIENT_KEY_EXCHANGE, (no CERTIFICATE_VERIFY), CCS, FINISHED, flight 5)
			rs = waitForFlightReceived("flight 3", collector, 4);
			// Handle and answer (should be CCS, FINISHED, flight 6)
			HandshakeException handshakeException = processAll(serverHandshaker, rs);

			assertNotNull(handshakeException);

			// Ensure handshake failed
			assertFalse("server handshake not failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			// Ensure handshake failed
			int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
			Throwable error = clientSessionListener.waitForSessionFailed(timeout, TimeUnit.MILLISECONDS);
			assertNotNull("client handshake not failed", error);
			assertThat(error, instanceOf(DtlsHandshakeTimeoutException.class));
			assertThat(clientConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawServer.stop();
		}
	}

	/**
	 * Test the server resuming handshake fails, if resumption verifier doesn't respond.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerResumeVerifierTimeout() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		DtlsConnectorConfig clientConfig = clientConfigBuilder.set(DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES, false).build();
		try {
			int remain = serverHelper.serverConnectionStore.remainingCapacity();

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					clientConnection, clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Ensure server side connection expects cid
			Connection serverSideConnection = serverHelper.serverConnectionStore.get(rawClient.getAddress());
			assertNotNull(serverSideConnection);
			boolean expectedCid = ConnectionId.useConnectionId(serverCidGenerator) && ConnectionId.supportsConnectionId(clientCidGenerator);
			assertThat(serverSideConnection.expectCid(), is(expectedCid));

			if (serverHelper.serverSessionStore == null || expectedCid) {
				// with cid, the connection is still accessible and therefore not removed.
				// without session store, a session-connection map is used and so the
				// connection is still accessible and therefore not removed.
				remain = serverHelper.serverConnectionStore.remainingCapacity();
			}

			resumeHandshakeResponses = 0; // no resumption verification response

			// Create resume handshaker
			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientHandshaker.getSession());
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					clientRecordLayer, timer, clientConnection, clientConfig, false);
			resumingClientHandshaker.addSessionListener(sessionListener);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			waitForAlertReceived("timeout", collector);

			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);
			Throwable error = serverSessionListener.waitForSessionFailed(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("server handshake not failed", error);
			assertThat(error, instanceOf(HandshakeException.class));
			assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remain));
		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server resuming handshake fails, if resumption verifier doesn't respond.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerResumeVerifierDoubleResponse() throws Exception {
		logging.setLoggingLevel("ERROR", DTLSConnector.class);
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		DtlsConnectorConfig clientConfig = clientConfigBuilder.set(DtlsConfig.DTLS_USE_MULTI_RECORD_MESSAGES, false).build();
		try {

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					clientConnection, clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Ensure server side connection expects cid
			Connection serverSideConnection = serverHelper.serverConnectionStore.get(rawClient.getAddress());
			assertNotNull(serverSideConnection);
			boolean expectedCid = ConnectionId.useConnectionId(serverCidGenerator) && ConnectionId.supportsConnectionId(clientCidGenerator);
			assertThat(serverSideConnection.expectCid(), is(expectedCid));

			resumeHandshakeResponses = 2; // double resumption verification response

			// Create resume handshaker
			sessionListener = new LatchSessionListener();
			DTLSSession resumableSession = new DTLSSession(clientHandshaker.getSession());
			ResumingClientHandshaker resumingClientHandshaker = new ResumingClientHandshaker(resumableSession,
					clientRecordLayer, timer, clientConnection, clientConfig, false);
			resumingClientHandshaker.addSessionListener(sessionListener);

			// Start resuming handshake (Send CLIENT HELLO, additional flight)
			resumingClientHandshaker.startHandshake();

			// Wait to receive response
			// (SERVER_HELLO, CHANGE CIPHER SPEC, FINISHED, flight 2)
			rs = waitForFlightReceived("flight 2", collector, 3);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer ( CHANGE CIPHER SPEC, FINISHED, flight 3)
			processAll(resumingClientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
			assertTrue("server handshake failed",
					serverSessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		} finally {
			rawClient.stop();
		}
	}

	@SuppressWarnings("deprecation")
	@Test
	public void testDisableHelloVerifyRequestForPsk() throws Exception {
		alternativeServerHelper = new ConnectorHelper(network);

		alternativeServerHelper.serverBuilder
				.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, RETRANSMISSION_TIMEOUT_MS, TimeUnit.MILLISECONDS)
				.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, MAX_RETRANSMISSIONS)
				.set(DtlsConfig.DTLS_USE_HELLO_VERIFY_REQUEST_FOR_PSK, false)
				.setConnectionIdGenerator(serverCidGenerator)
				.setHealthHandler(serverHealth);

		clientConfigBuilder
				.setAdvancedPskStore(new AdvancedSinglePskStore(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes()))
				.setAsList(DtlsConfig.DTLS_CIPHER_SUITES, CipherSuite.TLS_PSK_WITH_AES_128_CCM_8, CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient, true);
		try {
			// create limited server
			alternativeServerHelper.startServer();

			// Start connector
			rawClient.start();

			// Create handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					createConnection(clientCidGenerator, alternativeServerHelper.serverEndpoint), clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait for response (SERVER_HELLO, SERVER_DONE)
			List<Record> rs = waitForFlightReceived("flight 4", collector, 2);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait for response (CCS, FINISH)
			rs = waitForFlightReceived("flight 6", collector, 2);
			processAll(clientHandshaker, rs);

			// Ensure handshake succeeded
			assertTrue("server handshake failed",
					serverSessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		} finally {
			rawClient.stop();
			alternativeServerHelper.destroyServer();
			serverHealth.reset();
		}
	}

	@SuppressWarnings("deprecation")
	@Test
	public void testDisabledHelloVerifyRequestForPskWithCertificate() throws Exception {
		alternativeServerHelper = new ConnectorHelper(network);

		alternativeServerHelper.serverBuilder
				.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, RETRANSMISSION_TIMEOUT_MS, TimeUnit.MILLISECONDS)
				.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, MAX_RETRANSMISSIONS)
				.set(DtlsConfig.DTLS_USE_HELLO_VERIFY_REQUEST_FOR_PSK, false)
				.setConnectionIdGenerator(serverCidGenerator)
				.setHealthHandler(serverHealth);

		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient, true);
		try {
			// create limited server
			alternativeServerHelper.startServer();

			// Start connector
			rawClient.start();

			// Create handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					createConnection(clientCidGenerator, alternativeServerHelper.serverEndpoint), clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait for response (CCS, FINISH)
			rs = waitForFlightReceived("flight 6", collector, 2);
			processAll(clientHandshaker, rs);

			// Ensure handshake succeeded
			assertTrue("server handshake failed",
					serverSessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		} finally {
			rawClient.stop();
			alternativeServerHelper.destroyServer();
			serverHealth.reset();
		}
	}

	@Test
	public void testDisabledHelloVerifyRequestWithCertificate() throws Exception {
		alternativeServerHelper = new ConnectorHelper(network);

		alternativeServerHelper.serverBuilder
				.set(DtlsConfig.DTLS_RETRANSMISSION_TIMEOUT, RETRANSMISSION_TIMEOUT_MS, TimeUnit.MILLISECONDS)
				.set(DtlsConfig.DTLS_MAX_RETRANSMISSIONS, MAX_RETRANSMISSIONS)
				.set(DtlsConfig.DTLS_USE_HELLO_VERIFY_REQUEST, false)
				.setConnectionIdGenerator(serverCidGenerator)
				.setHealthHandler(serverHealth);

		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient, true);
		try {
			// create limited server
			alternativeServerHelper.startServer();

			// Start connector
			rawClient.start();

			// Create handshaker
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					createConnection(clientCidGenerator, alternativeServerHelper.serverEndpoint), clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			List<Record> rs = waitForFlightReceived("flight 4", collector, 5);

			// create server session listener to ensure,
			// that server finish also the handshake
			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait for response (CCS, FINISH)
			rs = waitForFlightReceived("flight 6", collector, 2);
			processAll(clientHandshaker, rs);

			// Ensure handshake succeeded
			assertTrue("server handshake failed",
					serverSessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			// Create 2. handshaker
			sessionListener = new LatchSessionListener();
			clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					createConnection(clientCidGenerator, alternativeServerHelper.serverEndpoint), clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 2. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);

			// create server session listener to ensure,
			// that server finish also the handshake
			serverSessionListener = getSessionListenerForEndpoint("server", rawClient);

			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake succeeded
			assertTrue("server handshake failed",
					serverSessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

		} finally {
			rawClient.stop();
			alternativeServerHelper.destroyServer();
			serverHealth.reset();
		}
	}

	/**
	 * Test the server handshake fails, if certificate provider doesn't respond.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerCertificateProviderTimeout() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {
			int remain = serverHelper.serverConnectionStore.remainingCapacity();
			certificateHandshakeResponses = 0; // no certificate provider response

			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					clientConnection, clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			waitForAlertReceived("timeout", collector);

			LatchSessionListener serverSessionListener = getSessionListenerForEndpoint("server", rawClient);
			Throwable error = serverSessionListener.waitForSessionFailed(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
			assertNotNull("server handshake not failed", error);
			assertThat(error, instanceOf(HandshakeException.class));
			assertThat(serverHelper.serverConnectionStore.remainingCapacity(), is(remain));

		} finally {
			rawClient.stop();
		}
	}

	/**
	 * Test the server handshake completes also by timeout.
	 * 
	 * @throws Exception if the test fails
	 */
	@Test
	public void testServerCompletesWithTimeout() throws Exception {
		// Configure and create UDP connector
		RecordCollectorDataHandler collector = new RecordCollectorDataHandler(clientCidGenerator);
		UdpConnector rawClient = new UdpConnector(LOCAL, collector);
		TestRecordLayer clientRecordLayer = new TestRecordLayer(rawClient);
		try {
			// Start connector
			rawClient.start();

			// Create handshaker
			Connection clientConnection = createClientConnection();
			LatchSessionListener sessionListener = new LatchSessionListener();
			ClientHandshaker clientHandshaker = new ClientHandshaker(null, clientRecordLayer, timer,
					clientConnection, clientConfigBuilder.build(), false);
			clientHandshaker.addSessionListener(sessionListener);

			// Start 1. handshake (Send CLIENT HELLO)
			clientHandshaker.startHandshake();

			// Wait to receive response (should be HELLO VERIFY REQUEST)
			List<Record> rs = waitForFlightReceived("flight 2", collector, 1);
			// Handle and answer (CLIENT HELLO with cookie)
			processAll(clientHandshaker, rs);

			// Wait for response (SERVER_HELLO, CERTIFICATE, ... , SERVER_DONE)
			rs = waitForFlightReceived("flight 4", collector, 5);
			// Handle and answer
			// (CERTIFICATE, CHANGE CIPHER SPEC, ..., FINISHED)
			processAll(clientHandshaker, rs);

			// Wait to receive response from server
			// (CHANGE CIPHER SPEC, FINISHED)
			rs = waitForFlightReceived("flight 6", collector, 2);
			// Handle (CHANGE CIPHER SPEC, FINISHED)
			processAll(clientHandshaker, rs);

			// Ensure handshake is successfully done
			assertTrue("client handshake failed",
					sessionListener.waitForSessionEstablished(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));

			TestConditionTools.assertStatisticCounter(serverHealth, "handshakes succeeded", is(1L),
					HANDSHAKE_EXPIRES_MS, TimeUnit.MILLISECONDS);

		} finally {
			rawClient.stop();
			serverHealth.reset();
		}
	}

	private void send(Connection connection, TestRecordLayer recordLayer, DTLSMessage... messages)
			throws GeneralSecurityException, IOException {
		List<DatagramPacket> datagrams = encode(connection, messages);
		recordLayer.sendFlight(datagrams);
	}

	private List<DatagramPacket> encode(Connection connection, DTLSMessage... messages)
			throws GeneralSecurityException, IOException {
		List<DatagramPacket> datagrams = new ArrayList<>();
		DTLSContext dtlsContext = connection.getDtlsContext();
		InetSocketAddress peerAddress = connection.getPeerAddress();
		for (DTLSMessage message : messages) {
			Record record = new Record(message.getContentType(), dtlsContext.getWriteEpoch(), message,
					dtlsContext, true, 0);
			byte[] data = record.toByteArray();
			DatagramPacket datagram = new DatagramPacket(data, data.length, peerAddress.getAddress(),
					peerAddress.getPort());
			datagrams.add(datagram);
		}
		return datagrams;
	}

	private void sendHelloVerifyRequest(RecordLayer recordLayer, List<Record> records)
			throws GeneralSecurityException, HandshakeException, IOException {
		if (records.size() == 1) {
			Record record = records.get(0);
			record.decodeFragment(DTLSConnectionState.NULL);
			final ClientHello clientHello = (ClientHello) record.getFragment();
			if (!clientHello.hasCookie()) {
				HelloVerifyRequest request = new HelloVerifyRequest(clientHello.getProtocolVersion(),
						new byte[] { 0, 1, 2, 3 });
				request.setMessageSeq(clientHello.getMessageSeq());
				// use epoch 0 and sequence no from CLIENT_HELLO record as
				// mandated by section 4.2.1 of the DTLS 1.2 spec
				// see http://tools.ietf.org/html/rfc6347#section-4.2.1
				Record helloVerify = new Record(ContentType.HANDSHAKE, clientHello.getProtocolVersion(),
						record.getSequenceNumber(), request);
				helloVerify.setAddress(record.getPeerAddress(), null);
				byte[] helloVerifyBytes = helloVerify.toByteArray();
				DatagramPacket datagram = new DatagramPacket(helloVerifyBytes, helloVerifyBytes.length,
						record.getPeerAddress());
				recordLayer.sendFlight(Arrays.asList(datagram));
			} else {
				throw new IllegalArgumentException(
						"client_hello contains already a cookie!");
			}
		} else {
			throw new IllegalArgumentException(
					"flight must contain exactly one handshake message, not " + records.size() + "!");
		}
	}

	private HandshakeException processAll(final Handshaker handshaker, final List<Record> records)
			throws GeneralSecurityException, HandshakeException {
		final AtomicReference<HandshakeException> cause = new AtomicReference<>();
		final CountDownLatch ready = new CountDownLatch(1);
		Runnable run = new Runnable() {

			@Override
			public void run() {
				try {
					DTLSContext dtlsContext = handshaker.getDtlsContext();
					for (Record record : records) {
						record.decodeFragment(dtlsContext.getReadState());
						handshaker.processMessage(record);
					}
				} catch (HandshakeException t) {
					LOGGER.error("process handshake", t);
					cause.set(t);
				} catch (Throwable t) {
					LOGGER.error("process handshake", t);
				}
				ready.countDown();
			}
		};
		SerialExecutor serialExecutor = handshaker.getConnection().getExecutor();
		if (serialExecutor != null) {
			serialExecutor.execute(run);
			try {
				// sometimes the flight is intended to be resend,
				// so the serialized execution must have finished.
				ready.await();
			} catch (InterruptedException e) {
			}
		} else {
			run.run();
		}
		return cause.get();
	}

	private Record waitForAlertReceived(String description, RecordCollectorDataHandler collector)
			throws InterruptedException {
		int timeout = RETRANSMISSION_TIMEOUT_MS * (2 << (MAX_RETRANSMISSIONS + 2));
		List<Record> rs = collector.waitForFlight(1, timeout, TimeUnit.MILLISECONDS);
		assertNotNull(description + " missing alert!", rs);
		assertThat(description + " unexpected records!", rs.size(), is(1));

		// Ensure handshake failed
		Record record = rs.get(0);
		assertThat(description + " unexpected record type " + record.getType(), record.getType(),
				is(ContentType.ALERT));
		return record;
	}

	private List<Record> waitForFlightReceived(String description, RecordCollectorDataHandler collector, int records)
			throws InterruptedException {
		List<Record> rs = collector.waitForFlight(records, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
		if (records == 0 && rs == null) {
			return Collections.emptyList();
		}
		if (rs == null) {
			assertNotNull(description + " timeout", rs);
		}
		if (rs.size() != records && lastReceivedFlight != null && lastReceivedFlight.size() <= rs.size()) {
			// check for retransmission
			int index = 0;
			int lastSize = lastReceivedFlight.size();
			for (; index < lastSize; ++index) {
				Record record1 = lastReceivedFlight.get(index);
				Record record2 = rs.get(index);
				if (record2.getEpoch() != record1.getEpoch()) {
					break;
				}
				if (record2.getType() != record1.getType()) {
					break;
				}
				if (record2.getFragmentLength() != record1.getFragmentLength()) {
					break;
				}
				if (record2.getSequenceNumber() > record1.getSequenceNumber()) {
					break;
				}
			}
			if (index == lastSize) {
				// retransmission
				if (lastSize == rs.size()) {
					// wait for next flight
					rs = collector.waitForFlight(records, MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS);
					assertNotNull(description + " timeout", rs);
				} else {
					// drop records of retransmitted flight
					List<Record> newFlight = new ArrayList<Record>();
					for (; index < rs.size(); ++index) {
						newFlight.add(rs.get(index));
					}
					rs = newFlight;
				}
			}
		}
		if (rs.size() != records) {
			for (Record record : rs) {
				if (record.getEpoch() == 0) {
					try {
						record.decodeFragment(DTLSConnectionState.NULL);
						record.getFragment();
					} catch (GeneralSecurityException e) {
						LOGGER.error("", e);
					} catch (HandshakeException e) {
						LOGGER.error("", e);
					}
				}
				LOGGER.info(" {}", record);
			}
			if (rs.size() < records) {
				assertThat(description + " missing records", rs.size(), is(records));
			} else {
				assertThat(description + " extra records", rs.size(), is(records));
			}
		}
		lastReceivedFlight = rs;
		return rs;
	}

	private void assertFlightRecordsRetransmitted(final List<Record> flight1, final List<Record> flight2) {

		assertThat("retransmitted flight has different number of records", flight2.size(), is(flight1.size()));
		for (int index = 0; index < flight1.size(); ++index) {
			Record record1 = flight1.get(index);
			Record record2 = flight2.get(index);
			assertThat("retransmitted flight record has different epoch", record2.getEpoch(), is(record1.getEpoch()));
			assertThat("retransmitted flight record has different type", record2.getType(), is(record1.getType()));
			assertThat("retransmitted flight record has different lenght", record2.getFragmentLength(),
					is(record1.getFragmentLength()));
			assertThat("retransmitted flight record has no newer seqn", record2.getSequenceNumber(),
					is(greaterThan(record1.getSequenceNumber())));
		}
	}

	private void assertSessionState(String side, UdpConnector endpoint, SessionState state, long timeout, TimeUnit unit)
			throws InterruptedException {
		LatchSessionListener sessionListener = getSessionListenerForEndpoint(side, endpoint);
		switch (state) {
		case ESTABLISHED:
			assertTrue(side + " handshake failed", sessionListener.waitForSessionEstablished(timeout, unit));
			break;
		case COMPLETED:
			if (sessionListener.waitForSessionEstablished(timeout, unit)) {
				assertTrue(side + " handshake not completed", sessionListener.waitForSessionCompleted(timeout, unit));
			} else {
				fail(side + " handshake failed");
			}
			break;
		case FAILED:
			assertNotNull(side + " handshake succeded", sessionListener.waitForSessionFailed(timeout, unit));
			break;
		}
	}

	private LatchSessionListener getSessionListenerForEndpoint(String side, UdpConnector endpoint) {
		InetSocketAddress address = endpoint.getAddress();
		LatchSessionListener sessionListener = serverHelper.sessionListenerMap.get(address);
		if (sessionListener == null && alternativeServerHelper != null) {
			sessionListener = alternativeServerHelper.sessionListenerMap.get(address);
		}
		assertNotNull("missing " + side + "-side session listener for " + address, sessionListener);
		return sessionListener;
	}

	private Connection createServerConnection() {
		Connection serverConnection = createConnection(serverCidGenerator, client.getAddress());
		serverHelper.serverConnectionStore.put(serverConnection);
		return serverConnection;
	}

	private Connection createClientConnection() {
		return createConnection(clientCidGenerator, serverHelper.serverEndpoint);
	}

	private Connection createConnection(ConnectionIdGenerator cidGenerator, InetSocketAddress peer) {
		ConnectionId cid = cidGenerator != null ? cidGenerator.createConnectionId() : null;
		if (cid == null) {
			// dummy cid as used by connection store
			byte[] cidBytes = new byte[4];
			RandomManager.currentRandom().nextBytes(cidBytes);
			cid = new ConnectionId(cidBytes);
		}
		Connection connection = new Connection(peer);
		connection.setConnectorContext(executor, null);
		connection.setConnectionId(cid);
		return connection;
	}

	public static class TestRecordLayer implements RecordLayer {

		private final AtomicInteger droppedRecords = new AtomicInteger();
		private final AtomicBoolean reverse = new AtomicBoolean();
		private final AtomicInteger drop = new AtomicInteger(0);
		private final AtomicInteger lastSentDatagrams = new AtomicInteger(0);
		protected final UdpConnector connector;

		public TestRecordLayer(UdpConnector connector) {
			this.connector = connector;
		}

		public TestRecordLayer(UdpConnector connector, boolean reverse) {
			this.connector = connector;
			setReverse(reverse);
		}

		public void setDrop(int drop) {
			this.drop.set(drop);
		}

		public void setReverse(boolean reverse) {
			this.reverse.set(reverse);
		}

		public int getLastSentDatagrams() {
			return lastSentDatagrams.get();
		}

		@Override
		public void sendFlight(List<DatagramPacket> flight) throws IOException {
			lastSentDatagrams.set(0);
			for (DatagramPacket datagram : getMessagesOfFlight(flight)) {
				connector.send(datagram);
				lastSentDatagrams.incrementAndGet();
			}
		}

		private List<DatagramPacket> getMessagesOfFlight(List<DatagramPacket> flight) {
			List<DatagramPacket> messages = flight;
			int drop = this.drop.get();
			if (drop != 0) {
				int index;
				if (drop < 0) {
					index = messages.size() + drop;
				} else {
					index = drop - 1;
				}
				if (0 <= index && index < messages.size()) {
					LOGGER.debug("Drop message {}, {} bytes.", index, messages.get(index).getLength());
					messages = new ArrayList<DatagramPacket>(flight);
					messages.remove(index);
				} else {
					LOGGER.warn("Can't drop message {}, out of range [0-{}].", drop, messages.size() - 1);
				}
			}
			if (this.reverse.get()) {
				if (messages.size() > 1) {
					LOGGER.debug("Reverse {} messages.", messages.size());
					messages = new ArrayList<DatagramPacket>(messages);
					Collections.reverse(messages);
				}
			}
			return messages;
		}

		@Override
		public void processRecord(Record record, Connection connection) {
			// records are fetched with getMessagesOfFlight and
			// handed over to the handshaker within the test
		}

		@Override
		public void processHandshakeException(Connection connection, HandshakeException error) {
		}

		@Override
		public boolean isRunning() {
			return connector.running.get();
		}

		@Override
		public int getMaxDatagramSize(boolean ipv6) {
			return DEFAULT_IPV6_MTU - IPV6_HEADER_LENGTH;
		}

		@Override
		public void dropReceivedRecord(Record record) {
			droppedRecords.incrementAndGet();
		}
	};
}
