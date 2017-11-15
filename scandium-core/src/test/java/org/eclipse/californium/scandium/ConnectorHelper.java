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
 ******************************************************************************/
package org.eclipse.californium.scandium;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.Connection;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.DtlsTestTools;
import org.eclipse.californium.scandium.dtls.InMemoryConnectionStore;
import org.eclipse.californium.scandium.dtls.InMemorySessionCache;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;

/**
 * A utility class for implementing DTLS integration tests.
 * <p>
 * Encapsulates a server side {@code DTLSConnector}.
 */
public class ConnectorHelper {

	static final String	CLIENT_IDENTITY						= "Client_identity";
	static final String	CLIENT_IDENTITY_SECRET				= "secretPSK";
	static final int	MAX_TIME_TO_WAIT_SECS				= 2;
	static final int	SERVER_CONNECTION_STORE_CAPACITY	= 2;


	DTLSConnector server;
	InetSocketAddress serverEndpoint;
	InMemoryConnectionStore serverConnectionStore;
	InMemorySessionCache serverSessionCache;
	SimpleRawDataChannel serverRawDataChannel;
	RawDataProcessor serverRawDataProcessor;
	DTLSSession establishedServerSession;

	private static DtlsConnectorConfig serverConfig;

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

		serverRawDataProcessor = new MessageCapturingProcessor();
		serverSessionCache = new InMemorySessionCache();
		serverConnectionStore = new InMemoryConnectionStore(SERVER_CONNECTION_STORE_CAPACITY, 5 * 60, serverSessionCache); // connection timeout 5mins
		serverRawDataChannel = new SimpleRawDataChannel(serverRawDataProcessor);

		InMemoryPskStore pskStore = new InMemoryPskStore();
		pskStore.setKey(CLIENT_IDENTITY, CLIENT_IDENTITY_SECRET.getBytes());
		serverConfig = new DtlsConnectorConfig.Builder(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
			.setSupportedCipherSuites(
				new CipherSuite[]{
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
						CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
						CipherSuite.TLS_PSK_WITH_AES_128_CCM_8,
						CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256})
			.setIdentity(DtlsTestTools.getPrivateKey(), DtlsTestTools.getServerCertificateChain(), true)
			.setTrustStore(DtlsTestTools.getTrustedCertificates())
			.setPskStore(pskStore)
			.setClientAuthenticationRequired(true)
			.build();

		server = new DTLSConnector(serverConfig, serverConnectionStore);
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
		serverRawDataChannel.setProcessor(serverRawDataProcessor);
		server.setErrorHandler(null);
	}

	static DtlsConnectorConfig newStandardClientConfig(final InetSocketAddress bindAddress) throws IOException, GeneralSecurityException {
		return newStandardClientConfigBuilder(bindAddress).build();
	}

	static DtlsConnectorConfig.Builder newStandardClientConfigBuilder(final InetSocketAddress bindAddress) throws IOException, GeneralSecurityException {
		return new DtlsConnectorConfig.Builder(bindAddress)
				.setIdentity(DtlsTestTools.getClientPrivateKey(), DtlsTestTools.getClientCertificateChain(), true)
				.setTrustStore(DtlsTestTools.getTrustedCertificates());
	}

	void givenAnEstablishedSession(final DTLSConnector client) throws Exception {
		givenAnEstablishedSession(client, true);
	}

	void givenAnEstablishedSession(final DTLSConnector client, boolean releaseSocket) throws Exception {
		givenAnEstablishedSession(client, new RawData("Hello World".getBytes(), serverEndpoint), releaseSocket);
	}

	void givenAnEstablishedSession(final DTLSConnector client, RawData msgToSend, boolean releaseSocket) throws Exception {

		CountDownLatch latch = new CountDownLatch(1);
		LatchDecrementingRawDataChannel clientChannel = new LatchDecrementingRawDataChannel();
		clientChannel.setLatch(latch);
		client.setRawDataReceiver(clientChannel);
		client.start();
		client.send(msgToSend);

		assertTrue("DTLS handshake timed out after " + MAX_TIME_TO_WAIT_SECS + " seconds", latch.await(MAX_TIME_TO_WAIT_SECS, TimeUnit.SECONDS));
		Connection con = serverConnectionStore.get(client.getAddress());
		assertNotNull(con);
		establishedServerSession = con.getEstablishedSession();
		assertNotNull(establishedServerSession);
		if (releaseSocket) {
			synchronized (client) {
				client.releaseSocket();
				// in order to prevent sporadic BindExceptions during test execution
				// give OS some time before allowing test cases to re-bind to same port
				client.wait(200);
			}
		}
	}

	class LatchDecrementingRawDataChannel extends SimpleRawDataChannel {
		private CountDownLatch latch;

		public LatchDecrementingRawDataChannel() {
			super(null);
		}

		public synchronized void setLatch(CountDownLatch latchToDecrement) {
			this.latch = latchToDecrement;
		}

		@Override
		public synchronized void receiveData(RawData raw) {
			super.receiveData(raw);
			if (latch != null) {
				latch.countDown();
			}
		}
	}

	class SimpleRawDataChannel implements RawDataChannel {

		private RawDataProcessor processor;

		public SimpleRawDataChannel(final RawDataProcessor processor) {
			setProcessor(processor);
		}

		public void setProcessor(final RawDataProcessor processor) {
			this.processor = processor;
		}

		@Override
		public void receiveData(final RawData raw) {
			if (processor != null) {
				RawData response = this.processor.process(raw);
				if (response != null) {
					server.send(response);
				}
			}
		}
	}

	static interface RawDataProcessor {

		RawData process(RawData request);

		RawData getLatestInboundMessage();

		Principal getClientIdentity();
	}

	static class MessageCapturingProcessor implements RawDataProcessor {
		private AtomicReference<RawData> inboundMessage = new AtomicReference<RawData>();

		@Override
		public RawData process(RawData request) {
			inboundMessage.set(request);
			return new RawData("ACK".getBytes(), request.getInetSocketAddress());
		}

		@Override
		public Principal getClientIdentity() {
			if (inboundMessage != null) {
				return inboundMessage.get().getSenderIdentity();
			} else {
				return null;
			}
		}

		@Override
		public RawData getLatestInboundMessage() {
			return inboundMessage.get();
		}
	}

	/**
	 * A handler for raw byte arrays.
	 *
	 */
	static interface DataHandler {

		void handleData(byte[] data);
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
		public void handleData(byte[] data) {
			if (process(data))
				latch.countDown();
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

	static class UdpConnector {

		final InetSocketAddress address;
		final DataHandler handler;
		final AtomicBoolean running = new AtomicBoolean();
		DatagramSocket socket;
		Thread receiver;

		public UdpConnector(final InetSocketAddress bindToAddress, final DataHandler dataHandler, final DtlsConnectorConfig config) {
			this.address = bindToAddress;
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
								handler.handleData(Arrays.copyOfRange(packet.getData(), packet.getOffset(), packet.getLength()));
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
	}
}
