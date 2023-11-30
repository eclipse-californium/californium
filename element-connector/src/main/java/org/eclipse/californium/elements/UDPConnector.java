/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.LinkedBlockingQueue;

import org.eclipse.californium.elements.UdpMulticastConnector.Builder;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.UdpConfig;
import org.eclipse.californium.elements.exception.EndpointMismatchException;
import org.eclipse.californium.elements.util.Bytes;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.StringUtil;
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
 * Note: using IPv6 interfaces with multiple addresses including permanent and
 * temporary (with potentially several different prefixes) currently causes
 * issues on the server side. The outgoing traffic in response to incoming may
 * select a different source address than the incoming destination address. To
 * overcome this, please ensure that the 'any address' is not used on the server
 * side and a separate Connector is created for each address to receive incoming
 * traffic.
 * 
 * UDP broadcast is allowed.
 * 
 * The number of threads can be set through
 * {@link UdpConfig#UDP_RECEIVER_THREAD_COUNT} and
 * {@link UdpConfig#UDP_SEND_BUFFER_SIZE} in the provided {@link Configuration}.
 */
public class UDPConnector implements Connector {
	/**
	 * The logger.
	 * 
	 * @deprecated scope will change to private.
	 */
	@Deprecated
	public static final Logger LOGGER = LoggerFactory.getLogger(UDPConnector.class);

	static final ThreadGroup ELEMENTS_THREAD_GROUP = new ThreadGroup("Californium/Elements"); //$NON-NLS-1$

	static {
		ELEMENTS_THREAD_GROUP.setDaemon(false);
	}

	/**
	 * Provided local address.
	 */
	protected final InetSocketAddress localAddr;
	/**
	 * List of receiver threads.
	 */
	private final List<Thread> receiverThreads = new LinkedList<Thread>();
	/**
	 * List of sender threads.
	 */
	private final List<Thread> senderThreads = new LinkedList<Thread>();

	/** The outbound message queue. */
	private final BlockingQueue<RawData> outgoing;

	/**
	 * The list of multicast receivers.
	 * 
	 * @since 3.0
	 */
	private final List<UdpMulticastConnector> multicastReceivers = new CopyOnWriteArrayList<>();

	private final int senderCount;
	private final int receiverCount;
	private final int receiverPacketSize;
	private final Integer configReceiveBufferSize;
	private final Integer configSendBufferSize;

	protected volatile boolean running;

	private volatile DatagramSocket socket;

	protected volatile InetSocketAddress effectiveAddr;

	/**
	 * Endpoint context matcher for outgoing messages.
	 * 
	 * @see #setEndpointContextMatcher(EndpointContextMatcher)
	 */
	private volatile EndpointContextMatcher endpointContextMatcher;

	/** The receiver of incoming messages. */
	private volatile RawDataChannel receiver;

	private Integer receiveBufferSize;
	private Integer sendBufferSize;

	/**
	 * {@code true}, if socket is reused, {@code false}, otherwise.
	 * 
	 * @since 2.3
	 */
	private boolean reuseAddress;

	/**
	 * {@code true}, if connector is a multicast receiver, {@code false},
	 * otherwise. A multicast receiver is a {@link UdpMulticastConnector}, if it
	 * joins exactly one multicast group or is bound to broadcast and no
	 * additional multicast group. {@link Builder#setMulticastReceiver(boolean)}
	 * must also be set to {@code true}.
	 * 
	 * @since 2.3
	 */
	protected boolean multicast;

	/**
	 * Creates a connector bound to a given IP address and port.
	 * 
	 * Note: using IPv6 interfaces with multiple addresses including permanent
	 * and temporary (with potentially several different prefixes) currently
	 * causes issues on the server side. The outgoing traffic in response to
	 * incoming may select a different source address than the incoming
	 * destination address. To overcome this, please ensure that the 'any
	 * address' is not used on the server side and a separate Connector is
	 * created for each address to receive incoming traffic.
	 * 
	 * @param address the IP address and port, if {@code null} the connector is
	 *            bound to an ephemeral port on the wildcard address
	 * @param configuration configuration with {@link UdpConfig} definitions.
	 */
	public UDPConnector(InetSocketAddress address, Configuration configuration) {
		if (address == null) {
			this.localAddr = new InetSocketAddress(0);
		} else {
			this.localAddr = address;
		}
		this.running = false;
		this.effectiveAddr = localAddr;
		this.outgoing = new LinkedBlockingQueue<RawData>(configuration.get(UdpConfig.UDP_CONNECTOR_OUT_CAPACITY));
		this.receiverCount = configuration.get(UdpConfig.UDP_RECEIVER_THREAD_COUNT);
		this.senderCount = configuration.get(UdpConfig.UDP_SENDER_THREAD_COUNT);
		this.receiverPacketSize = configuration.get(UdpConfig.UDP_DATAGRAM_SIZE);
		this.configReceiveBufferSize = configuration.get(UdpConfig.UDP_RECEIVE_BUFFER_SIZE);
		this.configSendBufferSize = configuration.get(UdpConfig.UDP_SEND_BUFFER_SIZE);
		this.receiveBufferSize = configReceiveBufferSize;
		this.sendBufferSize = configSendBufferSize;
	}

	@Override
	public boolean isRunning() {
		return running;
	}

	@Override
	public synchronized void start() throws IOException {

		if (running) {
			return;
		}

		for (UdpMulticastConnector multicastReceiver : multicastReceivers) {
			multicastReceiver.start();
		}

		DatagramSocket socket = new DatagramSocket(null);
		socket.setReuseAddress(reuseAddress);
		socket.bind(localAddr);
		init(socket);
	}

	/**
	 * Initialize connector using the provided socket.
	 * 
	 * @param socket datagram socket for communication
	 * @throws IOException if there is an error in the datagram socket calls.
	 */
	protected void init(DatagramSocket socket) throws IOException {
		this.socket = socket;
		effectiveAddr = (InetSocketAddress) socket.getLocalSocketAddress();

		if (configReceiveBufferSize != null) {
			socket.setReceiveBufferSize(configReceiveBufferSize);
		}
		receiveBufferSize = socket.getReceiveBufferSize();

		if (configSendBufferSize != null) {
			socket.setSendBufferSize(configSendBufferSize);
		}
		sendBufferSize = socket.getSendBufferSize();

		// running only, if the socket could be opened
		running = true;

		// start receiver and sender threads
		LOGGER.info("UDPConnector starts up {} sender threads and {} receiver threads", senderCount, receiverCount);

		for (int i = 0; i < receiverCount; i++) {
			receiverThreads.add(new Receiver("UDP-Receiver-" + localAddr + "[" + i + "]"));
		}

		if (!multicast) {
			for (int i = 0; i < senderCount; i++) {
				senderThreads.add(new Sender("UDP-Sender-" + localAddr + "[" + i + "]"));
			}
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
			LOGGER.debug("UDPConnector on [{}] stopping ...", effectiveAddr);
			for (Connector receiver : multicastReceivers) {
				receiver.stop();
			}

			// stop all threads
			for (Thread t : senderThreads) {
				t.interrupt();
			}
			for (Thread t : receiverThreads) {
				t.interrupt();
			}
			outgoing.drainTo(pending);
			if (socket != null) {
				socket.close();
				socket = null;
			}
			// stop all threads
			for (Thread t : senderThreads) {
				t.interrupt();
				try {
					t.join(1000);
				} catch (InterruptedException e) {
				}
			}
			senderThreads.clear();
			for (Thread t : receiverThreads) {
				t.interrupt();
				try {
					t.join(1000);
				} catch (InterruptedException e) {
				}
			}
			receiverThreads.clear();
			LOGGER.debug("UDPConnector on [{}] has stopped.", effectiveAddr);
		}
		for (RawData data : pending) {
			notifyMsgAsInterrupted(data);
		}
	}

	@Override
	public void destroy() {
		stop();
		for (Connector receiver : multicastReceivers) {
			receiver.destroy();
		}
		receiver = null;
	}

	@Override
	public void send(RawData msg) {
		if (msg == null) {
			throw new NullPointerException("Message must not be null");
		}
		if (multicast) {
			throw new IllegalStateException("Connector is a multicast receiver!");
		}
		if (msg.getInetSocketAddress().getPort() == 0) {
			String destination = StringUtil.toString(msg.getInetSocketAddress());
			LOGGER.trace("Discarding message with {} bytes to [{}] without destination-port",
					msg.getSize(), destination);
			msg.onError(new IOException("CoAP message to " + destination + " dropped, destination port 0!"));
			return;
		}

		// move onError callback out of synchronized block
		boolean running;
		boolean added = false;
		synchronized (this) {
			running = this.running;
			if (running) {
				added = outgoing.offer(msg);
			}
		}
		if (!running) {
			notifyMsgAsInterrupted(msg);
		} else if (!added) {
			msg.onError(new InterruptedIOException("Connector overloaded."));
		}
	}

	@Override
	public void setRawDataReceiver(RawDataChannel receiver) {
		this.receiver = receiver;
		for (UdpMulticastConnector multicastReceiver : multicastReceivers) {
			multicastReceiver.setRawDataReceiver(receiver);
		}
	}

	@Override
	public void setEndpointContextMatcher(EndpointContextMatcher matcher) {
		this.endpointContextMatcher = matcher;
		for (UdpMulticastConnector multicastReceiver : multicastReceivers) {
			multicastReceiver.setEndpointContextMatcher(matcher);
		}
	}

	/**
	 * Add multicast-receiver.
	 * 
	 * @param multicastReceiver multicast-receiver.
	 * @throws NullPointerException if multicastReceiver is {@code null}
	 * @throws IllegalArgumentException if connector is not valid as multicast
	 *             receiver
	 * @throws IllegalStateException if connector itself is a multicast receiver
	 * @since 3.0
	 */
	public void addMulticastReceiver(UdpMulticastConnector multicastReceiver) {
		if (multicastReceiver == null) {
			throw new NullPointerException("Connector must not be null!");
		}
		if (!multicastReceiver.isMutlicastReceiver()) {
			throw new IllegalArgumentException("Connector is no valid multicast receiver!");
		}
		if (multicast) {
			throw new IllegalStateException("Connector itself is a multicast receiver!");
		}
		multicastReceivers.add(multicastReceiver);
		multicastReceiver.setRawDataReceiver(receiver);
	}

	/**
	 * Remove multicast-receiver.
	 * 
	 * If removed successful, reset raw-data-receiver to {@code null}.
	 * 
	 * @param multicastReceiver multicast-receiver.
	 * @since 3.0
	 */
	public void removeMulticastReceiver(UdpMulticastConnector multicastReceiver) {
		if (multicastReceivers.remove(multicastReceiver)) {
			multicastReceiver.setRawDataReceiver(null);
		}
	}

	@Override
	public InetSocketAddress getAddress() {
		return effectiveAddr;
	}

	private void notifyMsgAsInterrupted(RawData msg) {
		msg.onError(new InterruptedIOException("Connector is not running."));
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
				} catch (InterruptedIOException t) {
					LOGGER.trace("Network stage thread [{}] was stopped successfully at:", getName(), t);
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

		private final DatagramPacket datagram;
		private final int size;

		private Receiver(String name) {
			super(name);
			// we add one byte to be able to detect potential truncation.
			this.size = receiverPacketSize + 1;
			this.datagram = new DatagramPacket(new byte[size], size);
		}

		protected void work() throws IOException {
			datagram.setLength(size);
			DatagramSocket currentSocket = socket;
			if (currentSocket != null) {
				currentSocket.receive(datagram);
				processDatagram(datagram);
			}
		}
	}

	private class Sender extends NetworkStageThread {

		private final DatagramPacket datagram;

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
				LOGGER.warn("UDPConnector ({}) drops {} bytes to {}", effectiveAddr, datagram.getLength(),
						StringUtil.toLog(destinationAddress));
				raw.onError(new EndpointMismatchException("UDP sending"));
				return;
			}
			datagram.setData(raw.getBytes());
			datagram.setSocketAddress(destinationAddress);

			DatagramSocket currentSocket = socket;
			if (currentSocket != null) {
				try {
					raw.onContextEstablished(connectionContext);
					currentSocket.send(datagram);
					raw.onSent();
				} catch (IOException ex) {
					raw.onError(ex);
				}
				LOGGER.debug("UDPConnector ({}) sent {} bytes to {}", this, datagram.getLength(),
						StringUtil.toLog(destinationAddress));
			} else {
				raw.onError(new IOException("socket already closed!"));
			}
		}
	}

	/**
	 * Process received datagram.
	 * 
	 * Convert {@link DatagramPacket} into {@link RawData} and pass it to the
	 * {@link RawDataChannel}.
	 * 
	 * @param datagram received datagram.
	 * @since 2.5
	 */
	@Override
	public void processDatagram(DatagramPacket datagram) {
		InetSocketAddress connector = effectiveAddr;
		RawDataChannel dataReceiver = receiver;
		if (datagram.getPort() == 0) {
			// RFC 768
			// Source Port is an optional field, when meaningful, it indicates
			// the port of the sending process, and may be assumed to be the
			// port to which a reply should be addressed in the absence of any
			// other information. If not used, a value of zero is inserted.
			LOGGER.trace("Discarding message with {} bytes from [{}] without source-port",
					datagram.getLength(), StringUtil.toLog(datagram.getSocketAddress()));
			return;
		}
		if (datagram.getLength() > receiverPacketSize) {
			// too large datagram for our buffer! data could have been
			// truncated, so we discard it.
			LOGGER.debug(
					"UDPConnector ({}) received truncated UDP datagram from {}. Maximum size allowed {}. Discarding ...",
					connector, StringUtil.toLog(datagram.getSocketAddress()), receiverPacketSize);
		} else if (dataReceiver == null) {
			LOGGER.debug("UDPConnector ({}) received UDP datagram from {} without receiver. Discarding ...", connector,
					StringUtil.toLog(datagram.getSocketAddress()));
		} else {
			long timestamp = ClockUtil.nanoRealtime();
			String local = StringUtil.toString(connector);
			if (multicast) {
				local = "mc/" + local;
			}
			LOGGER.debug("UDPConnector ({}) received {} bytes from {}", local, datagram.getLength(),
					StringUtil.toLog(datagram.getSocketAddress()));
			byte[] bytes = Arrays.copyOfRange(datagram.getData(), datagram.getOffset(), datagram.getLength());
			RawData msg = RawData.inbound(bytes,
					new UdpEndpointContext(new InetSocketAddress(datagram.getAddress(), datagram.getPort())), multicast,
					timestamp, connector);
			dataReceiver.receiveData(msg);
		}
	}

	/**
	 * Get reuse address.
	 * 
	 * @return {@code true}, if connector may reuse address, {@code false}
	 *         otherwise.
	 * 
	 * @see DatagramSocket#getReuseAddress()
	 * @since 2.3
	 */
	public boolean getReuseAddress() {
		return reuseAddress;
	}

	/**
	 * Set reuse address.
	 * 
	 * @param enable {@code true}, if connector may reuse address, {@code false}
	 *            otherwise.
	 * @see DatagramSocket#setReuseAddress(boolean)
	 * @since 2.3
	 */
	public void setReuseAddress(boolean enable) {
		this.reuseAddress = enable;
	}

	public Integer getReceiveBufferSize() {
		return receiveBufferSize;
	}

	public Integer getSendBufferSize() {
		return sendBufferSize;
	}

	public int getReceiverThreadCount() {
		return receiverCount;
	}

	public int getSenderThreadCount() {
		return senderCount;
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
		return getProtocol() + "-" + StringUtil.toString(getAddress());
	}
}
