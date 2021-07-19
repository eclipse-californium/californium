/*******************************************************************************
 * Copyright (c) 2015, 2019 Bosch Software Innovations GmbH and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - Initial creation
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 464383
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix 464812
 *    Kai Hudalla (Bosch Software Innovations GmbH) - add support for stale
 *                                                    session expiration (466554)
 *    Kai Hudalla (Bosch Software Innovations GmbH) - replace SessionStore with ConnectionStore
 *                                                    keeping all information about the connection
 *                                                    to a peer in a single place
 *    Kai Hudalla (Bosch Software Innovations GmbH) - fix bug 472196
 *    Achim Kraus, Kai Hudalla (Bosch Software Innovations GmbH) - add test case for bug 478538
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use DtlsTestTools' accessors to explicitly retrieve
 *                                                    client & server keys and certificate chains
 *    Bosch Software Innovations GmbH - add test cases for GitHub issue #1
 *    Achim Kraus (Bosch Software Innovations GmbH) - expose client channel to ensure, that
 *                                                    a server response is received before shutdown
 *                                                    the connector
 *    Achim Kraus (Bosch Software Innovations GmbH) - use connector in SimpleRawDataChannel
 *                                                    for sending responses instead fixed server
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.PersistentConnector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.elements.auth.ExtensiblePrincipal;
import org.eclipse.californium.elements.config.CertificateAuthenticationMode;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.TestThreadFactory;
import org.eclipse.californium.scandium.config.DtlsConfig;
import org.eclipse.californium.scandium.config.DtlsConfig.DtlsRole;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.ConnectionIdGenerator;
import org.eclipse.californium.scandium.dtls.DTLSConnectionState;
import org.eclipse.californium.scandium.dtls.DTLSContext;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DebugConnectionStore;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.Handshaker;
import org.eclipse.californium.scandium.dtls.TestInMemorySessionStore;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.ResumptionSupportingConnectionStore;
import org.eclipse.californium.scandium.dtls.SessionAdapter;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite.KeyExchangeAlgorithm;
import org.eclipse.californium.scandium.dtls.pskstore.AdvancedMultiPskStore;
import org.eclipse.californium.scandium.dtls.x509.NewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.SingleCertificateProvider;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier;
import org.eclipse.californium.scandium.dtls.x509.StaticNewAdvancedCertificateVerifier.Builder;
import org.eclipse.californium.scandium.rule.DtlsNetworkRule;

/**
 * A utility class for implementing DTLS integration tests.
 * <p>
 * Encapsulates a server side {@code DTLSConnector}.
 */
public class ConnectorHelper {

	static final String SERVERNAME = "my.test.server";
	static final String SERVERNAME2 = "my.test.server2";
	static final String SCOPED_CLIENT_IDENTITY = "My_client_identity";
	static final String SCOPED_CLIENT_IDENTITY_SECRET = "mySecretPSK";
	static final String CLIENT_IDENTITY = "Client_identity";
	static final String CLIENT_IDENTITY_SECRET = "secretPSK";
	static final int MAX_TIME_TO_WAIT_SECS = 2;
	static final int SERVER_CONNECTION_STORE_CAPACITY = 3;

	static final ThreadFactory TEST_UDP_THREAD_FACTORY = new TestThreadFactory("TEST-UDP-");

	boolean useSessionStore;
	DTLSConnector server;
	InetSocketAddress serverEndpoint;
	DebugConnectionStore serverConnectionStore;
	TestInMemorySessionStore serverSessionStore;
	SimpleRawDataChannel serverRawDataChannel;
	RawDataProcessor serverRawDataProcessor;
	Map<InetSocketAddress, LatchSessionListener> sessionListenerMap = new ConcurrentHashMap<>();
	DTLSContext establishedServerContext;
	DTLSSession establishedServerSession;
	AlertCatcher serverAlertCatcher;
	AdvancedMultiPskStore serverPskStore;

	DtlsConnectorConfig serverConfig;
	DtlsConnectorConfig.Builder serverBuilder;

	public ConnectorHelper(DtlsNetworkRule network) {
		List<CipherSuite> list = new ArrayList<>(CipherSuite.getEcdsaCipherSuites(false));
		list.addAll(CipherSuite.getCipherSuitesByKeyExchangeAlgorithm(false, KeyExchangeAlgorithm.ECDHE_PSK,
				KeyExchangeAlgorithm.PSK));
		serverPskStore = new AdvancedMultiPskStore();
		serverPskStore.setKey(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
		serverPskStore.setKey(SCOPED_CLIENT_IDENTITY, SCOPED_CLIENT_IDENTITY_SECRET.getBytes(), SERVERNAME);

		serverBuilder = DtlsConnectorConfig.builder(network.createTestConfig())
				.set(DtlsConfig.DTLS_ROLE, DtlsRole.SERVER_ONLY)
				.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 1)
				.set(DtlsConfig.DTLS_CONNECTOR_THREAD_COUNT, 2)
				.set(DtlsConfig.DTLS_MAX_CONNECTIONS, SERVER_CONNECTION_STORE_CAPACITY)
				.set(DtlsConfig.DTLS_STALE_CONNECTION_THRESHOLD, 5, TimeUnit.MINUTES)
				.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
				.setAdvancedPskStore(serverPskStore)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getPrivateKey(),
						DtlsTestTools.getServerCertificateChain(), CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509))
				.set(DtlsConfig.DTLS_RECOMMENDED_CIPHER_SUITES_ONLY, false)
				.setSupportedCipherSuites(list)
				.setLoggingTag("server");
	}

	/**
	 * Configures and starts a connector representing the <em>server side</em>
	 * of a DTLS connection.
	 * <p>
	 * The connector is configured as follows:
	 * <ul>
	 * <li>binds to an ephemeral port on loopback address, the address can be
	 * read from the <em>serverEndpoint</em> property</li>
	 * <li>supports ECDHE_ECDSA and PSK based ciphers using both CCM and
	 * CBC</li>
	 * <li>uses a PSK store containing the {@link #CLIENT_IDENTITY} and matching
	 * secret</li>
	 * <li>uses the private key returned by
	 * {@link DtlsTestTools#getPrivateKey()}</li>
	 * <li>uses {@link DtlsTestTools#getTrustedCertificates()} as the trust
	 * anchor</li>
	 * </ul>
	 * 
	 * @param builder pre-configuration
	 * @throws IOException if the server cannot be started.
	 * @throws GeneralSecurityException if the keys cannot be read.
	 */
	public void startServer() throws IOException, GeneralSecurityException {

		ensureTrusts(serverBuilder);

		serverConfig = serverBuilder.build();

		if (useSessionStore) {
			serverSessionStore = new TestInMemorySessionStore(false);
		}
		serverConnectionStore = new DebugConnectionStore(serverConfig.getMaxConnections(),
				serverConfig.getStaleConnectionThresholdSeconds(), serverSessionStore);
		serverConnectionStore.setTag("server");

		serverAlertCatcher = new AlertCatcher();

		server = new DtlsTestConnector(serverConfig, serverConnectionStore);
		serverRawDataProcessor = new MessageCapturingProcessor();
		serverRawDataChannel = new SimpleRawDataChannel(server, serverRawDataProcessor);
		server.setRawDataReceiver(serverRawDataChannel);
		server.setAlertHandler(serverAlertCatcher);
		server.start();
		serverEndpoint = server.getAddress();
	}

	public NewAdvancedCertificateVerifier ensureTrusts(DtlsConnectorConfig.Builder builder) {
		NewAdvancedCertificateVerifier result = null;
		DtlsConnectorConfig incompleteConfig = builder.getIncompleteConfig();
		if (incompleteConfig.getCertificateAuthenticationMode() != CertificateAuthenticationMode.NONE) {
			if (incompleteConfig.getAdvancedCertificateVerifier() == null) {
				Builder verifierBuilder = StaticNewAdvancedCertificateVerifier.builder();
				X509Certificate[] trustedCertificates = DtlsTestTools.getTrustedCertificates();
				verifierBuilder.setTrustedCertificates(trustedCertificates);
				verifierBuilder.setTrustAllRPKs();
				result = verifierBuilder.build();
				builder.setAdvancedCertificateVerifier(result);
			}
		}
		return result;
	}

	/**
	 * Shuts down and destroys the encapsulated server side connector.
	 */
	public void destroyServer() {
		cleanUpServer();
		if (server != null) {
			server.destroy();
		}
	}

	/**
	 * Resets the encapsulated server side connector's state to its initial
	 * configuration.
	 * <p>
	 * This entails:
	 * <ul>
	 * <li>clear server's connection store</li>
	 * <li>re-set server's {@code RawDataChannel}'s processor to
	 * <em>serverRawDataProcessor</em></li>
	 * <li>clear server's error handler</li>
	 * </ul>
	 */
	public void cleanUpServer() {
		if (serverConnectionStore != null) {
			serverConnectionStore.clear();
		}
		if (serverSessionStore != null) {
			serverSessionStore.clear();
		}
		if (serverRawDataProcessor != null) {
			serverRawDataProcessor.clear();
		}
		if (serverRawDataChannel != null) {
			serverRawDataChannel.setProcessor(serverRawDataProcessor);
		}
		if (serverAlertCatcher != null) {
			serverAlertCatcher.resetAlert();
			if (server != null) {
				server.setAlertHandler(serverAlertCatcher);
			}
		} else if (server != null) {
			server.setAlertHandler(null);
		}
		sessionListenerMap.clear();
	}

	/**
	 * Remove connect from server side connection store.
	 * 
	 * @param client address of client
	 * @param removeFromSessionCache {@code true} remove from session cache
	 *            also.
	 */
	public void remove(InetSocketAddress client, boolean removeFromSessionCache) {
		Connection connection = serverConnectionStore.get(client);
		if (connection != null) {
			serverConnectionStore.remove(connection, removeFromSessionCache);
		}
	}

	public DTLSConnector createClient(DtlsConnectorConfig configuration) {
		return new DtlsTestConnector(configuration);
	}

	public DTLSConnector createClient(DtlsConnectorConfig configuration,
			ResumptionSupportingConnectionStore connectionStore) {
		return new DtlsTestConnector(configuration, connectionStore);
	}

	public DtlsConnectorConfig.Builder newClientConfigBuilder(DtlsNetworkRule network) throws IOException, GeneralSecurityException {
		InetSocketAddress clientEndpoint = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
		NewAdvancedCertificateVerifier clientCertificateVerifier = StaticNewAdvancedCertificateVerifier.builder()
				.setTrustedCertificates(DtlsTestTools.getTrustedCertificates()).setTrustAllRPKs().build();
		return DtlsConnectorConfig.builder(network.createTestConfig())
				.set(DtlsConfig.DTLS_ROLE, DtlsRole.CLIENT_ONLY)
				.setLoggingTag("client")
				.setAddress(clientEndpoint)
				.set(DtlsConfig.DTLS_RECEIVER_THREAD_COUNT, 1)
				.set(DtlsConfig.DTLS_CONNECTOR_THREAD_COUNT, 2)
				.setCertificateIdentityProvider(new SingleCertificateProvider(DtlsTestTools.getClientPrivateKey(),
						DtlsTestTools.getClientCertificateChain(), CertificateType.RAW_PUBLIC_KEY,
						CertificateType.X_509))
				.setAdvancedCertificateVerifier(clientCertificateVerifier);
	}

	LatchDecrementingRawDataChannel givenAnEstablishedSession(DTLSConnector client, boolean releaseSocket)
			throws Exception {
		RawData raw = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(serverEndpoint), null,
				false);
		return givenAnEstablishedSession(client, raw, releaseSocket);
	}

	LatchDecrementingRawDataChannel givenAnEstablishedSession(DTLSConnector client, RawData msgToSend,
			boolean releaseSocket) throws Exception {

		LatchDecrementingRawDataChannel clientChannel = new LatchDecrementingRawDataChannel(1);
		client.setRawDataReceiver(clientChannel);
		client.start();
		clientChannel.setAddress(client.getAddress());
		client.send(msgToSend);
		assertTrue("DTLS handshake timed out after " + MAX_TIME_TO_WAIT_SECS + " seconds",
				clientChannel.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		Connection con = serverConnectionStore.get(client.getAddress());
		assertNotNull(con);
		establishedServerContext = con.getDtlsContext();
		assertNotNull(establishedServerContext);
		establishedServerSession = con.getEstablishedSession();
		assertNotNull(establishedServerSession);
		if (releaseSocket) {
			synchronized (client) {
				client.stop();
				// in order to prevent sporadic BindExceptions during test
				// execution
				// give OS some time before allowing test cases to re-bind to
				// same port
				client.wait(200);
			}
		}
		return clientChannel;
	}

	static void assertPrincipalHasAdditionalInfo(Principal peerIdentity, String key, String expectedValue) {
		assertThat(peerIdentity, instanceOf(ExtensiblePrincipal.class));
		@SuppressWarnings("unchecked")
		ExtensiblePrincipal<? extends Principal> p = (ExtensiblePrincipal<? extends Principal>) peerIdentity;
		assertThat(p.getExtendedInfo().get(key, String.class), is(expectedValue));
	}

	public static void assertReloadConnections(String tag, PersistentConnector connector) {
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			int saveCount = connector.saveConnections(out, 1000);
			byte[] data1 = out.toByteArray();
			int readCount = connector.loadConnections(new ByteArrayInputStream(data1), 0);
			assertEquals(tag + " read mismatch", saveCount, readCount);
			out = new ByteArrayOutputStream();
			int saveCount2 = connector.saveConnections(out, 1000);
			byte[] data2 = out.toByteArray();
			assertEquals(tag + " 2. save mismatch", saveCount, saveCount2);
			assertTrue(tag + " data mismatch", Arrays.equals(data1, data2));
		} catch (IllegalStateException e) {
			e.printStackTrace();
			fail(tag + ": " + e.getMessage());
		} catch (IOException e) {
			e.printStackTrace();
			fail(tag + " io-error: " + e.getMessage());
		}
	}

	static class LatchDecrementingRawDataChannel implements RawDataChannel {

		private InetSocketAddress address;
		private CountDownLatch latch;

		public LatchDecrementingRawDataChannel() {
		}

		public LatchDecrementingRawDataChannel(int count) {
			setLatchCount(count);
		}

		public synchronized InetSocketAddress getAddress() {
			return address;
		}

		public synchronized void setAddress(InetSocketAddress address) {
			this.address = address;
		}

		public synchronized void setLatchCount(int count) {
			this.latch = new CountDownLatch(count);
		}

		private synchronized CountDownLatch getLatch() {
			return this.latch;
		}

		@Override
		public void receiveData(RawData raw) {
			CountDownLatch latch = getLatch();
			if (latch != null) {
				latch.countDown();
			}
		}

		public boolean await(long timeout, TimeUnit unit) throws InterruptedException {
			CountDownLatch latch = getLatch();
			if (latch != null) {
				return latch.await(timeout, unit);
			} else {
				return false;
			}
		}
	}

	static class SimpleRawDataChannel extends LatchDecrementingRawDataChannel {

		private RawDataProcessor processor;
		private DTLSConnector connector;

		public SimpleRawDataChannel() {
		}

		public SimpleRawDataChannel(DTLSConnector connector, RawDataProcessor processor) {
			if (connector == null) {
				throw new NullPointerException("connector must not be null!");
			}
			this.connector = connector;
			setProcessor(processor);
		}

		public synchronized void setProcessor(RawDataProcessor processor) {
			if (processor != null && connector == null) {
				throw new IllegalStateException("connector must be provided when creating the instance!");
			}
			this.processor = processor;
		}

		@Override
		public void receiveData(final RawData raw) {
			DTLSConnector connector;
			RawDataProcessor processor;
			synchronized (this) {
				processor = this.processor;
				connector = this.connector;
			}
			if (processor != null) {
				RawData response = processor.process(raw);
				if (response != null && connector != null) {
					InetSocketAddress socketAddress = connector.getAddress();
					setAddress(socketAddress);
					connector.send(response);
				}
			}
		}
	}

	static interface RawDataProcessor {

		RawData process(RawData request);

		RawData getLatestInboundMessage();

		EndpointContext getClientEndpointContext();

		boolean quiet(long quietMillis, long timeoutMillis) throws InterruptedException;

		void clear();
	}

	static class MessageCapturingProcessor implements RawDataProcessor {

		private volatile boolean quiet;
		private AtomicLong time = new AtomicLong(System.nanoTime());
		private AtomicReference<RawData> inboundMessage = new AtomicReference<RawData>();

		@Override
		public RawData process(RawData request) {
			time.set(System.nanoTime());
			if (quiet) {
				return null;
			}
			inboundMessage.set(request);
			return RawData.outbound("ACK".getBytes(), request.getEndpointContext(), null, false);
		}

		@Override
		public EndpointContext getClientEndpointContext() {
			RawData data = inboundMessage.get();
			if (data != null) {
				return data.getEndpointContext();
			} else {
				return null;
			}
		}

		@Override
		public RawData getLatestInboundMessage() {
			return inboundMessage.get();
		}

		@Override
		public boolean quiet(long quietMillis, long timeoutMillis) throws InterruptedException {
			quiet = true;
			try {
				long quietNanos = TimeUnit.MILLISECONDS.toNanos(quietMillis);
				long leftNanos = TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
				long endNanos = System.nanoTime() + leftNanos;
				while (leftNanos > 0) {
					long delta = System.nanoTime() - time.get();
					if (delta > quietNanos) {
						return true;
					}
					delta = quietNanos - delta;
					if (leftNanos < delta) {
						return false;
					}
					delta = TimeUnit.NANOSECONDS.toMillis(delta);
					if (delta < 1) {
						delta = 1;
					}
					Thread.sleep(delta);
					leftNanos = endNanos - System.nanoTime();
				}
				return (System.nanoTime() - time.get()) > quietNanos;
			} finally {
				quiet = false;
			}
		}

		public void clear() {
			inboundMessage.set(null);
		}
	}

	/**
	 * A handler for raw byte arrays.
	 *
	 */
	static interface DataHandler {

		void handleData(InetSocketAddress endpoint, byte[] data);
	}

	static class RecordCollectorDataHandler implements DataHandler {

		private BlockingQueue<List<Record>> records = new LinkedBlockingQueue<>();
		private Map<Integer, DTLSConnectionState> apply = new HashMap<>(8);
		private final ConnectionIdGenerator cidGenerator;

		RecordCollectorDataHandler() {
			this(null);
		}

		RecordCollectorDataHandler(ConnectionIdGenerator cidGenerator) {
			this.cidGenerator = cidGenerator;
		}

		/**
		 * Apply session to all collected records with matching epoch.
		 * 
		 * @param session session to be applied. {@code null} is applied to
		 *            epoch 0.
		 */
		void applyDtlsContext(DTLSContext context) {
			if (context == null) {
				apply.put(0, DTLSConnectionState.NULL);
			} else {
				apply.put(context.getReadEpoch(), context.getReadState());
			}
		}

		@Override
		public void handleData(InetSocketAddress endpoint, byte[] data) {
			try {
				List<Record> messages = DtlsTestTools.fromByteArray(data, cidGenerator, ClockUtil.nanoRealtime());
				for (Record record : messages) {
					record.setAddress(endpoint, null);
				}
				records.put(messages);
			} catch (InterruptedException e) {
			}
		}

		public List<Record> waitForRecords(long timeout, TimeUnit unit) throws InterruptedException {
			List<Record> result = records.poll(timeout, unit);
			if (result != null) {
				for (Record record : result) {
					if (apply.containsKey(record.getEpoch())) {
						try {
							record.decodeFragment(apply.get(record.getEpoch()));
						} catch (GeneralSecurityException e) {
							throw new IllegalStateException(e);
						} catch (HandshakeException e) {
							throw new IllegalStateException(e);
						}
					}
				}
			}
			return result;
		}

		public List<Record> waitForFlight(int size, long timeout, TimeUnit unit) throws InterruptedException {
			long timeoutNanos = unit.toNanos(timeout);
			long time = ClockUtil.nanoRealtime();
			long end = time + timeoutNanos;
			List<Record> received = waitForRecords(timeoutNanos, TimeUnit.NANOSECONDS);
			if (null != received && received.size() < size) {
				received = new ArrayList<Record>(received);
				timeoutNanos = end - ClockUtil.nanoRealtime();
				while (0 < timeoutNanos && received.size() < size) {
					List<Record> next = waitForRecords(timeoutNanos, TimeUnit.NANOSECONDS);
					if (next != null) {
						received.addAll(next);
					}
					timeoutNanos = end - ClockUtil.nanoRealtime();
				}
			}
			return received;
		}

		public List<Record> assertFlight(int size, long timeout, TimeUnit unit) throws InterruptedException {
			List<Record> received = waitForFlight(size, timeout, unit);
			assertThat("timeout: flight not received", received, is(notNullValue()));
			int left = Math.max(size - received.size(), 0);
			assertThat("timeout: flight missing records", left, is(0));
			return received;
		}

	};

	public static enum SessionState {
		ESTABLISHED, COMPLETED, FAILED
	}

	public static class LatchSessionListener extends SessionAdapter {

		private CountDownLatch finished = new CountDownLatch(1);
		private AtomicBoolean established = new AtomicBoolean();
		private CountDownLatch completed = new CountDownLatch(1);
		private AtomicReference<Throwable> error = new AtomicReference<Throwable>();

		@Override
		public void contextEstablished(Handshaker handshaker, DTLSContext establishedContext)
				throws HandshakeException {
			established.set(true);
			finished.countDown();
		}

		@Override
		public void handshakeCompleted(Handshaker handshaker) {
			completed.countDown();
		}

		@Override
		public void handshakeFailed(Handshaker handshaker, Throwable error) {
			this.error.set(error);
			finished.countDown();
		}

		public boolean waitForSessionEstablished(long timeout, TimeUnit unit) throws InterruptedException {
			return finished.await(timeout, unit) && established.get();
		}

		public boolean waitForSessionCompleted(long timeout, TimeUnit unit) throws InterruptedException {
			if (waitForSessionEstablished(timeout, unit)) {
				return completed.await(timeout, unit);
			}
			return false;
		}

		public Throwable waitForSessionFailed(long timeout, TimeUnit unit) throws InterruptedException {
			if (finished.await(timeout, unit)) {
				return error.get();
			}
			return null;
		}
	};

	static class UdpConnector {

		final InetSocketAddress address;
		final DataHandler handler;
		final AtomicBoolean running = new AtomicBoolean();
		final Thread receiver;
		volatile DatagramSocket socket;

		public UdpConnector(final int port, final DataHandler dataHandler) {
			this.address = new InetSocketAddress(InetAddress.getLoopbackAddress(), port);
			this.handler = dataHandler;
			Runnable rec = new Runnable() {

				@Override
				public void run() {
					byte[] buf = new byte[8192];
					DatagramPacket packet = new DatagramPacket(buf, buf.length);
					while (running.get()) {
						try {
							DatagramSocket socket = getSocket();
							socket.receive(packet);
							if (packet.getLength() > 0) {
								// handle data
								handler.handleData((InetSocketAddress) packet.getSocketAddress(),
										Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getLength()));
								packet.setLength(buf.length);
							}
						} catch (IOException e) {
							// do nothing
						}
					}
				}
			};
			receiver = TEST_UDP_THREAD_FACTORY.newThread(rec);
		}

		public void start() throws IOException {
			if (running.compareAndSet(false, true)) {
				socket = new DatagramSocket(address);
				receiver.start();
			}
		}

		public void stop() {
			if (running.compareAndSet(true, false)) {
				socket.close();
				receiver.interrupt();
				try {
					receiver.join(2000);
				} catch (InterruptedException e) {
				}
			}
		}

		public void send(DatagramPacket datagram) throws IOException {
			DatagramSocket socket = getSocket();
			if (!socket.isClosed()) {
				socket.send(datagram);
			}
		}

		public void sendRecord(InetSocketAddress peerAddress, byte[] record) throws IOException {
			DatagramPacket datagram = new DatagramPacket(record, record.length, peerAddress.getAddress(),
					peerAddress.getPort());
			send(datagram);
		}

		public final InetSocketAddress getAddress() {
			DatagramSocket socket = getSocket();
			if (socket == null) {
				return address;
			} else {
				return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
			}
		}

		private DatagramSocket getSocket() {
			return socket;
		}
	}

	class DtlsTestConnector extends DTLSConnector {

		DtlsTestConnector(DtlsConnectorConfig configuration) {
			super(configuration);
		}

		DtlsTestConnector(DtlsConnectorConfig configuration, ResumptionSupportingConnectionStore connectionStore) {
			super(configuration, connectionStore);
		}

		@Override
		protected void onInitializeHandshaker(final Handshaker handshaker) {
			LatchSessionListener listener = new LatchSessionListener();
			handshaker.addSessionListener(listener);
			sessionListenerMap.put(handshaker.getPeerAddress(), listener);
		}
	}

	public static interface BuilderSetup {

		void setup(DtlsConnectorConfig.Builder builder);
	}

	public static class BuilderSetups extends ArrayList<BuilderSetup> implements BuilderSetup {

		private static final long serialVersionUID = 8683452582211892189L;

		public BuilderSetups() {
		}

		public BuilderSetups(BuilderSetup setup) {
			add(setup);
		}

		public BuilderSetups(BuilderSetups setups, BuilderSetup setup) {
			super(setups.size() + 1);
			addAll(setups);
			add(setup);
		}

		@Override
		public void setup(DtlsConnectorConfig.Builder builder) {
			for (BuilderSetup setup : this) {
				setup.setup(builder);
			}
		}

		@Override
		public String toString() {
			StringBuilder line = new StringBuilder();
			for (BuilderSetup setup : this) {
				line.append(setup).append(", ");
			}
			if (line.length() > 2) {
				line.setLength(line.length() - 2);
			}
			return line.toString();
		}
	}

	@SafeVarargs
	public static BuilderSetup[] append(List<BuilderSetup>... modes) {
		List<BuilderSetup> appended = new ArrayList<>();
		for (List<BuilderSetup> list : modes) {
			for (BuilderSetup mode : list) {
				appended.add(mode);
			}
		}
		return appended.toArray(new BuilderSetup[appended.size()]);
	}

	@SafeVarargs
	public static BuilderSetup[] expand(List<BuilderSetup>... modes) {
		return expand(0, modes);
	}

	private static BuilderSetups[] expand(int index, List<BuilderSetup>[] modes) {
		if (index == modes.length) {
			return new BuilderSetups[] { new BuilderSetups() };
		}
		List<BuilderSetups> expand = new ArrayList<>();
		BuilderSetups[] temps = expand(index + 1, modes);
		for (BuilderSetup mode : modes[index]) {
			for (BuilderSetups temp : temps) {
				expand.add(new BuilderSetups(temp, mode));
			}
		}
		return expand.toArray(new BuilderSetups[expand.size()]);
	}

	public static class AlertCatcher implements AlertHandler {

		private AlertMessage alert;

		@Override
		public synchronized void onAlert(InetSocketAddress peer, AlertMessage alert) {
			if (this.alert == null) {
				this.alert = alert;
				notify();
			}
		}

		/**
		 * Reset current alert.
		 * 
		 * @since 3.0
		 */
		public synchronized void resetAlert() {
			this.alert = null;
		}

		/**
		 * Get alert.
		 * 
		 * @return alert, or {@code null}, if no alert was received.
		 * @since 3.0
		 */
		public synchronized AlertMessage getAlert() {
			return alert;
		}

		/**
		 * Wait for alert.
		 * 
		 * @return {@code AlertMessage} if reported, {@code null}, otherwise.
		 */
		public synchronized AlertMessage waitForAlert(long timeout, TimeUnit unit) throws InterruptedException {
			if (alert == null && timeout > 0) {
				long millis = unit.toMillis(timeout);
				if (millis <= 0) {
					millis = 1;
				}
				wait(millis);
			}
			return alert;
		}
	}

}
