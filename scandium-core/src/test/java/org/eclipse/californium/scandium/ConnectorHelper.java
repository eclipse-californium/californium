/*******************************************************************************
 * Copyright (c) 2015, 2016 Bosch Software Innovations GmbH and others.
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

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.InMemorySessionCache;
import org.eclipse.californium.scandium.dtls.Record;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;

/**
 * A utility class for implementing DTLS integration tests.
 * <p>
 * Encapsulates a server side {@code DTLSConnector}.
 */
public class ConnectorHelper {

	static final String SERVERNAME							= "my.test.server";
	static final String	SCOPED_CLIENT_IDENTITY				= "My_client_identity";
	static final String	CLIENT_IDENTITY						= "Client_identity";
	static final String	CLIENT_IDENTITY_SECRET				= "secretPSK";
	static final int	MAX_TIME_TO_WAIT_SECS				= 2;
	static final int	SERVER_CONNECTION_STORE_CAPACITY	= 3;


	DTLSConnector server;
	InetSocketAddress serverEndpoint;
	InMemoryConnectionStore serverConnectionStore;
	InMemorySessionCache serverSessionCache;
	SimpleRawDataChannel serverRawDataChannel;
	RawDataProcessor serverRawDataProcessor;
	DTLSSession establishedServerSession;

	DtlsConnectorConfig serverConfig;

	/**
	 * Configures and starts a connector representing the <em>server side</em> of a DTLS connection.
	 * <p>
	 * The connector is configured as follows:
	 * <ul>
	 * <li>binds to an ephemeral port on loopback address, the address can be read from the
	 * <em>serverEndpoint</em> property</li>
	 * <li>supports ECDHE_ECDSA and PSK based ciphers using both CCM and CBC</li>
	 * <li>uses a PSK store containing the {@link #CLIENT_IDENTITY} and matching secret</li>
	 * <li>uses the private key returned by {@link DtlsTestTools#getPrivateKey()}</li>
	 * <li>uses {@link DtlsTestTools#getTrustedCertificates()} as the trust anchor</li>
	 * <li>requires clients to be authenticated</li>
	 * </ul>
	 * 
	 * @throws IOException if the server cannot be started.
	 * @throws GeneralSecurityException if the keys cannot be read.
	 */
	public void startServer() throws IOException, GeneralSecurityException {
		DtlsConnectorConfig.Builder builder = new DtlsConnectorConfig.Builder();
		startServer(builder);
	}


	/**
	 * Configures and starts a connector representing the <em>server side</em> of a DTLS connection.
	 * <p>
	 * The connector is configured as follows:
	 * <ul>
	 * <li>binds to an ephemeral port on loopback address, the address can be read from the
	 * <em>serverEndpoint</em> property</li>
	 * <li>supports ECDHE_ECDSA and PSK based ciphers using both CCM and CBC</li>
	 * <li>uses a PSK store containing the {@link #CLIENT_IDENTITY} and matching secret</li>
	 * <li>uses the private key returned by {@link DtlsTestTools#getPrivateKey()}</li>
	 * <li>uses {@link DtlsTestTools#getTrustedCertificates()} as the trust anchor</li>
	 * </ul>
	 * 
	 * @param builder pre-configuration
	 * @throws IOException if the server cannot be started.
	 * @throws GeneralSecurityException if the keys cannot be read.
	 */
	public void startServer(DtlsConnectorConfig.Builder builder) throws IOException, GeneralSecurityException {

		serverSessionCache = new InMemorySessionCache();
		serverConnectionStore = new InMemoryConnectionStore(null, SERVER_CONNECTION_STORE_CAPACITY, 5 * 60, serverSessionCache); // connection timeout 5mins
		serverConnectionStore.setTag("server");

		InMemoryPskStore pskStore = new InMemoryPskStore();
		pskStore.setKey(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
		pskStore.setKey(SCOPED_CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes(), SERVERNAME);

		builder.setAddress(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
				.setSupportedCipherSuites(
							CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
							CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
							CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
							CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256)
				.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain(), CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509)
				.setPskStore(pskStore)
				.setMaxConnections(SERVER_CONNECTION_STORE_CAPACITY)
				.setMaxTransmissionUnit(1024)
				.setReceiverThreadCount(1)
				.setConnectionThreadCount(2)
				.setLoggingTag("server")
				.setServerOnly(true);

		if (!Boolean.FALSE.equals(builder.getIncompleteConfig().isClientAuthenticationRequired()) ||
				Boolean.TRUE.equals(builder.getIncompleteConfig().isClientAuthenticationWanted())) {
			builder.setTrustStore(DtlsTestTools.getTrustedCertificates()).setRpkTrustAll();
		}
		serverConfig = builder.build();

		server = new DTLSConnector(serverConfig, serverConnectionStore);
		serverRawDataProcessor = new MessageCapturingProcessor();
		serverRawDataChannel = new SimpleRawDataChannel(server);
		serverRawDataChannel.setProcessor(serverRawDataProcessor);
		server.setRawDataReceiver(serverRawDataChannel);
		server.start();
		serverEndpoint = server.getAddress();
	}

	/**
	 * Shuts down and destroys the encapsulated server side connector.
	 */
	public void destroyServer() {
		server.destroy();
	}

	/**
	 * Resets the encapsulated server side connector's state to its initial configuration.
	 * <p>
	 * This entails:
	 * <ul>
	 * <li>clear server's connection store</li>
	 * <li>re-set server's {@code RawDataChannel}'s processor to <em>serverRawDataProcessor</em></li>
	 * <li>clear server's error handler</li>
	 * </ul>
	 */
	public void cleanUpServer() {
		serverConnectionStore.clear();
		serverRawDataProcessor.clear();
		serverRawDataChannel.setProcessor(serverRawDataProcessor);
		server.setAlertHandler(null);
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

	static DtlsConnectorConfig newStandardClientConfig(final InetSocketAddress bindAddress) throws IOException, GeneralSecurityException {
		return newStandardClientConfigBuilder(bindAddress).build();
	}

	static DtlsConnectorConfig.Builder newStandardClientConfigBuilder(final InetSocketAddress bindAddress) throws IOException, GeneralSecurityException {
		return new DtlsConnectorConfig.Builder()
				.setLoggingTag("client")
				.setAddress(bindAddress)
				.setReceiverThreadCount(1)
				.setConnectionThreadCount(2)
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientCertificateChain(), CertificateType.RAW_PUBLIC_KEY, CertificateType.X_509)
				.setTrustStore(DtlsTestTools.getTrustedCertificates())
				.setRpkTrustAll();
	}

	LatchDecrementingRawDataChannel givenAnEstablishedSession(final DTLSConnector client) throws Exception {
		return givenAnEstablishedSession(client, true);
	}

	LatchDecrementingRawDataChannel givenAnEstablishedSession(final DTLSConnector client, boolean releaseSocket) throws Exception {
		RawData raw = RawData.outbound("Hello World".getBytes(), new AddressEndpointContext(serverEndpoint), null, false);
		return givenAnEstablishedSession(client, raw, releaseSocket);
	}

	LatchDecrementingRawDataChannel givenAnEstablishedSession(final DTLSConnector client, RawData msgToSend, boolean releaseSocket) throws Exception {

		CountDownLatch latch = new CountDownLatch(1);
		LatchDecrementingRawDataChannel clientChannel = new LatchDecrementingRawDataChannel(client);
		clientChannel.setLatch(latch);
		client.setRawDataReceiver(clientChannel);
		client.start();
		client.send(msgToSend);
		clientChannel.setAddress(client.getAddress());
		assertTrue("DTLS handshake timed out after " + MAX_TIME_TO_WAIT_SECS + " seconds", latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		Connection con = serverConnectionStore.get(client.getAddress());
		assertNotNull(con);
		establishedServerSession = con.getEstablishedSession();
		assertNotNull(establishedServerSession);
		if (releaseSocket) {
			synchronized (client) {
				client.stop();
				// in order to prevent sporadic BindExceptions during test execution
				// give OS some time before allowing test cases to re-bind to same port
				client.wait(200);
			}
		}
		return clientChannel;
	}

	static class LatchDecrementingRawDataChannel extends SimpleRawDataChannel {
		private CountDownLatch latch;

		public LatchDecrementingRawDataChannel(DTLSConnector server) {
			super(server);
		}

		public synchronized void setLatch(CountDownLatch latchToDecrement) {
			this.latch = latchToDecrement;
		}

		@Override
		public void receiveData(RawData raw) {
			super.receiveData(raw);
			synchronized (this) {
				if (latch != null) {
					latch.countDown();
				}
			}
		}
	}

	static class SimpleRawDataChannel implements RawDataChannel {

		private RawDataProcessor processor;
		private DTLSConnector connector;
		private InetSocketAddress address;
		
		public SimpleRawDataChannel(DTLSConnector connector) {
			this.connector = connector;
		}

		public synchronized void setProcessor(final RawDataProcessor processor) {
			this.processor = processor;
		}

		public synchronized InetSocketAddress getAddress() {
			return address;
		}

		public synchronized void setAddress(InetSocketAddress address) {
			this.address = address;
		}

		@Override
		public void receiveData(final RawData raw) {
			RawDataProcessor processor;
			synchronized (this) {
				processor = this.processor;
			}
			if (processor != null) {
				RawData response = processor.process(raw);
				if (response != null) {
					InetSocketAddress socketAddress = connector.getAddress();
					synchronized (this) {
						address = socketAddress;
					}
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

	/**
	 * A data handler that decrements a latch on successful processing of data.
	 *
	 */
	abstract class LatchDecrementingDataHandler implements DataHandler {

		private CountDownLatch latch;

		public LatchDecrementingDataHandler(final CountDownLatch latch){
			this.setLatch(latch);
		}

		@Override
		public void handleData(InetSocketAddress endpoint, byte[] data) {
			if (process(data)) {
				latch.countDown();
			}
		}

		/**
		 * Processes data in a context specific way.
		 * 
		 * @param data The data.
		 * @return {@code true} if the data has been processed successfully.
		 */
		public abstract boolean process(final byte[] data);

		public void setLatch(final CountDownLatch latch) {
			this.latch = latch;
		}
	};

	static class RecordCollectorDataHandler implements ConnectorHelper.DataHandler {

		private BlockingQueue<List<Record>> records = new LinkedBlockingQueue<>();

		@Override
		public void handleData(InetSocketAddress endpoint, byte[] data) {
			try {
				records.put(Record.fromByteArray(data, endpoint, null));
			} catch (InterruptedException e) {
			}
		}

		public List<Record> waitForRecords(long timeout, TimeUnit unit) throws InterruptedException {
			return records.poll(timeout, unit);
		}

		public List<Record> waitForFlight(int size, long timeout, TimeUnit unit) throws InterruptedException {
			long timeoutNanos = unit.toNanos(timeout);
			long time = System.nanoTime();
			List<Record> received = waitForRecords(timeoutNanos, TimeUnit.NANOSECONDS);
			if (null != received && received.size() < size) {
				received = new ArrayList<Record>(received);
				List<Record> next;
				timeoutNanos -= (System.nanoTime() - time);
				if (0 < timeoutNanos) {
					if (null != (next = waitForRecords(timeoutNanos, TimeUnit.NANOSECONDS))) {
						received.addAll(next);
					}
				}
			}
			return received;
		}
	};

	static class UdpConnector {

		final InetSocketAddress address;
		final DataHandler handler;
		final AtomicBoolean running = new AtomicBoolean();
		DatagramSocket socket;
		Thread receiver;

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
							socket.receive(packet);
							if (packet.getLength() > 0) {
								// handle data
								handler.handleData(address, Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getLength()));
								packet.setLength(buf.length);
							}
						} catch (IOException e) {
							// do nothing
						}
					}
				}
			};
			receiver = new Thread(rec);
		}

		public synchronized void start() throws IOException {
			if (running.compareAndSet(false, true)) {
				socket = new DatagramSocket(address);
				receiver.start();
			}
		}

		public synchronized void stop() {
			if (running.compareAndSet(true, false)) {
				socket.close();
			}
		}

		public void sendRecord(InetSocketAddress peerAddress, byte[] record) throws IOException {
			DatagramPacket datagram = new DatagramPacket(record, record.length, peerAddress.getAddress(), peerAddress.getPort());

			if (!socket.isClosed()) {
				socket.send(datagram);
			}
		}

		public final InetSocketAddress getAddress() {
			DatagramSocket socket;
			synchronized (this) {
				socket = this.socket;
			}
			if (socket == null) {
				return address;
			} else {
				return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
			}
		}
	}
}
