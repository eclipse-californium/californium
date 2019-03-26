/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and initial implementation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CorrelationContextMatcher
 *                                                    for outgoing messages
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - clear thread-list on stop
 *                                                    log exception when stopping.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add onSent and onError. 
 *                                                    issue #305
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix error stopping an connector,
 *                                                    when socket failed to open.
 *                                                    issue #345
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce protocol,
 *                                                    remove scheme
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - reduce logging on shutdown
 *    Achim Kraus (Bosch Software Innovations GmbH) - use UdpEndpointContext to prevent
 *                                                    matching with a DtlsEndpointContext
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix rare NullPointerException
 *                                                    on stop()
 *    Achim Kraus (Bosch Software Innovations GmbH) - make connector extendible to
 *                                                    support multicast sockets
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import org.eclipse.californium.elements.util.Bytes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link Connector} employing UDP as the transport protocol for exchanging
 * data between networked clients and a server application. It implements the
 * network stage in the Californium architecture.
 * 
 * In order to process data received from the network via UDP, client code can
 * register a {@link RawDataChannel} instance by means of the
 * {@link #setRawDataReceiver(RawDataChannel)} method. Sending data out to
 * connected clients can be achieved by means of the {@link #send(RawData)}
 * method.
 * 
 * UDP broadcast is allowed.
 * 
 * The number of threads can be set through {@link #setReceiverThreadCount(int)}
 * and {@link #setSenderThreadCount(int)} before the connector is started.
 */
public class UDPConnector implements Connector {

	public static final Logger LOGGER = LoggerFactory.getLogger(UDPConnector.class.getName());

	public static final int UNDEFINED = 0;

	static final ThreadGroup ELEMENTS_THREAD_GROUP = new ThreadGroup("Californium/Elements"); //$NON-NLS-1$

	protected volatile boolean running;

	protected final InetSocketAddress localAddr;

	private DatagramSocket socket;

	private volatile InetSocketAddress effectiveAddr;

	private List<Thread> receiverThreads;
	private List<Thread> senderThreads;

	/** The outbound message queue. */
	private final BlockingQueue<RawData> outgoing;

	/**
	 * Endpoint context matcher for outgoing messages.
	 * 
	 * @see #setEndpointContextMatcher(EndpointContextMatcher)
	 */
	private volatile EndpointContextMatcher endpointContextMatcher;

	/** The receiver of incoming messages. */
	private RawDataChannel receiver;

	private int receiveBufferSize = UNDEFINED;
	private int sendBufferSize = UNDEFINED;

	private int senderCount = 1;
	private int receiverCount = 1;

	private int receiverPacketSize = 2048;

	/**
	 * Creates a connector on the wildcard address listening on an ephemeral
	 * port, i.e. a port chosen by the system.
	 * 
	 * The effect of this constructor is the same as invoking
	 * <code>UDPConnector(null)</code>.
	 */
	public UDPConnector() {
		this(null);
	}

	/**
	 * Creates a connector bound to a given IP address and port.
	 * 
	 * @param address the IP address and port, if <code>null</code> the
	 *            connector is bound to an ephemeral port on the wildcard
	 *            address
	 */
	public UDPConnector(InetSocketAddress address) {
		if (address == null) {
			this.localAddr = new InetSocketAddress(0);
		} else {
			this.localAddr = address;
		}
		this.running = false;
		this.effectiveAddr = localAddr;
		// TODO: think about restricting the outbound queue's capacity
		this.outgoing = new LinkedBlockingQueue<RawData>();
	}

	@Override
	public synchronized void start() throws IOException {

		if (running) {
			return;
		}

		// if localAddr is null or port is 0, the system decides
		init(new DatagramSocket(localAddr.getPort(), localAddr.getAddress()));
	}

	/**
	 * Initialize connector using the provided socket.
	 * 
	 * @param socket datagram socket for communication
	 * @throws IOException  if there is an error in the datagram socket calls.
	 */
	protected void init(DatagramSocket socket) throws IOException {
		this.socket = socket;
		effectiveAddr = (InetSocketAddress) socket.getLocalSocketAddress();

		if (receiveBufferSize != UNDEFINED) {
			socket.setReceiveBufferSize(receiveBufferSize);
		}
		receiveBufferSize = socket.getReceiveBufferSize();

		if (sendBufferSize != UNDEFINED) {
			socket.setSendBufferSize(sendBufferSize);
		}
		sendBufferSize = socket.getSendBufferSize();

		// running only, if the socket could be opened
		running = true;

		// start receiver and sender threads
		LOGGER.info("UDPConnector starts up {} sender threads and {} receiver threads", senderCount, receiverCount);

		receiverThreads = new LinkedList<Thread>();
		for (int i = 0; i < receiverCount; i++) {
			receiverThreads.add(new Receiver("UDP-Receiver-" + localAddr + "[" + i + "]"));
		}

		senderThreads = new LinkedList<Thread>();
		for (int i = 0; i < senderCount; i++) {
			senderThreads.add(new Sender("UDP-Sender-" + localAddr + "[" + i + "]"));
		}

		for (Thread t : receiverThreads) {
			t.start();
		}
		for (Thread t : senderThreads) {
			t.start();
		}

		/*
		 * Java bug: sometimes, socket.getReceiveBufferSize() and
		 * socket.setSendBufferSize() block forever when called here. When
		 * called up there, it seems to work. This issue occurred in Java
		 * 1.7.0_09, Windows 7.
		 */

		LOGGER.info("UDPConnector listening on {}, recv buf = {}, send buf = {}, recv packet size = {}", effectiveAddr,
				receiveBufferSize, sendBufferSize, receiverPacketSize);
	}

	@Override
	public void stop() {
		// move onError callback out of synchronized block
		List<RawData> pending = new ArrayList<>(outgoing.size());
		synchronized (this) {
			if (!running) {
				return;
			}
			running = false;
			// stop all threads
			if (senderThreads != null) {
				for (Thread t : senderThreads) {
					t.interrupt();
				}
				senderThreads.clear();
				senderThreads = null;
			}
			if (receiverThreads != null) {
				for (Thread t : receiverThreads) {
					t.interrupt();
				}
				receiverThreads.clear();
				receiverThreads = null;
			}
			outgoing.drainTo(pending);
			if (socket != null) {
				socket.close();
				socket = null;
			}
			LOGGER.info("UDPConnector on [{}] has stopped.", effectiveAddr);
		}
		for (RawData data : pending) {
			notifyMsgAsInterrupted(data);
		}
	}

	@Override
	public void destroy() {
		stop();
	}

	@Override
	public void send(RawData msg) {
		if (msg == null) {
			throw new NullPointerException("Message must not be null");
		}
		// move onError callback out of synchronized block
		boolean running;
		synchronized (this) {
			running = this.running;
			if (running) {
				outgoing.add(msg);
			}
		}
		if (!running) {
			notifyMsgAsInterrupted(msg);
		}
	}

	@Override
	public void setRawDataReceiver(RawDataChannel receiver) {
		this.receiver = receiver;
	}

	@Override
	public void setEndpointContextMatcher(EndpointContextMatcher matcher) {
		this.endpointContextMatcher = matcher;
	}

	public InetSocketAddress getAddress() {
		return effectiveAddr;
	}

	private void notifyMsgAsInterrupted(RawData msg) {
		msg.onError(new InterruptedIOException("Connector is not running."));
	}

	private synchronized DatagramSocket getSocket() {
		return socket;
	}

	private abstract class NetworkStageThread extends Thread {

		/**
		 * Instantiates a new worker.
		 *
		 * @param name the name
		 */
		protected NetworkStageThread(String name) {
			super(ELEMENTS_THREAD_GROUP, name);
			setDaemon(true);
		}

		public void run() {
			LOGGER.debug("Starting network stage thread [{}]", getName());
			while (running) {
				try {
					work();
					if (!running) {
						LOGGER.debug("Network stage thread [{}] was stopped successfully", getName());
						break;
					}
				} catch (InterruptedException t) {
					LOGGER.trace("Network stage thread [{}] was stopped successfully at:", getName(), t);
				} catch (IOException t) {
					if (running) {
						LOGGER.error("Exception in network stage thread [{}]:", getName(), t);
					} else {
						LOGGER.trace("Network stage thread [{}] was stopped successfully at:", getName(), t);
					}
				} catch (Throwable t) {
					LOGGER.error("Exception in network stage thread [{}]:", getName(), t);
				}
			}
		}

		/**
		 * @throws Exception the exception to be properly logged
		 */
		protected abstract void work() throws Exception;
	}

	private class Receiver extends NetworkStageThread {

		private DatagramPacket datagram;
		private int size;

		private Receiver(String name) {
			super(name);
			// we add one byte to be able to detect potential truncation.
			this.size = receiverPacketSize + 1;
			this.datagram = new DatagramPacket(new byte[size], size);
		}

		protected void work() throws IOException {
			datagram.setLength(size);
			DatagramSocket currentSocket = getSocket();
			if (currentSocket != null) {
				currentSocket.receive(datagram);
				if (datagram.getLength() >= size) {
					// too large datagram for our buffer! data could have been
					// truncated, so we discard it.
					LOGGER.debug(
							"UDPConnector ({}) received truncated UDP datagram from {}:{}. Maximum size allowed {}. Discarding ...",
							effectiveAddr, datagram.getAddress(), datagram.getPort(), size - 1);
				} else {
					LOGGER.debug("UDPConnector ({}) received {} bytes from {}:{}", effectiveAddr, datagram.getLength(),
							datagram.getAddress(), datagram.getPort());
					byte[] bytes = Arrays.copyOfRange(datagram.getData(), datagram.getOffset(), datagram.getLength());
					RawData msg = RawData.inbound(bytes,
							new UdpEndpointContext(new InetSocketAddress(datagram.getAddress(), datagram.getPort())),
							false);
					receiver.receiveData(msg);
				}
			}
		}
	}

	private class Sender extends NetworkStageThread {

		private DatagramPacket datagram;

		private Sender(String name) {
			super(name);
			this.datagram = new DatagramPacket(Bytes.EMPTY, 0);
		}

		protected void work() throws InterruptedException {
			RawData raw = outgoing.take(); // Blocking
			/*
			 * check, if message should be sent with the "none endpoint context"
			 * of UDP connector
			 */
			EndpointContext destination = raw.getEndpointContext();
			InetSocketAddress destinationAddress = destination.getPeerAddress();
			EndpointContext connectionContext = new UdpEndpointContext(destinationAddress);
			EndpointContextMatcher endpointMatcher = UDPConnector.this.endpointContextMatcher;
			if (endpointMatcher != null && !endpointMatcher.isToBeSent(destination, connectionContext)) {
				LOGGER.warn("UDPConnector ({}) drops {} bytes to {}:{}", effectiveAddr, datagram.getLength(),
						destinationAddress.getAddress(), destinationAddress.getPort());
				raw.onError(new EndpointMismatchException());
				return;
			}
			datagram.setData(raw.getBytes());
			datagram.setSocketAddress(destinationAddress);

			DatagramSocket currentSocket = getSocket();
			if (currentSocket != null) {
				try {
					raw.onContextEstablished(connectionContext);
					currentSocket.send(datagram);
					raw.onSent();
				} catch (IOException ex) {
					raw.onError(ex);
				}
				LOGGER.debug("UDPConnector ({}) sent {} bytes to {}:{}", this, datagram.getLength(),
						datagram.getAddress(), datagram.getPort());
			} else {
				raw.onError(new IOException("socket already closed!"));
			}
		}
	}

	public void setReceiveBufferSize(int size) {
		this.receiveBufferSize = size;
	}

	public int getReceiveBufferSize() {
		return receiveBufferSize;
	}

	public void setSendBufferSize(int size) {
		this.sendBufferSize = size;
	}

	public int getSendBufferSize() {
		return sendBufferSize;
	}

	public void setReceiverThreadCount(int count) {
		this.receiverCount = count;
	}

	public int getReceiverThreadCount() {
		return receiverCount;
	}

	public void setSenderThreadCount(int count) {
		this.senderCount = count;
	}

	public int getSenderThreadCount() {
		return senderCount;
	}

	public void setReceiverPacketSize(int size) {
		this.receiverPacketSize = size;
	}

	public int getReceiverPacketSize() {
		return receiverPacketSize;
	}

	@Override
	public String getProtocol() {
		return "UDP";
	}

	@Override
	public String toString() {
		return getProtocol() + "-" + getAddress();
	}
}
