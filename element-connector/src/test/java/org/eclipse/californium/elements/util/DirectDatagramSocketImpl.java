/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation.
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove log level property and
 *                                                    redirect this to logging.properties
 *                                                    (handler must be adjusted anyway).
 *                                                    Set InterruptedException as cause.
 *    Achim Kraus (Bosch Software Innovations GmbH) - move "peekData" in to prevent the
 *                                                    DatagramSocket to use the erroneous
 *                                                    internal "old implementation mode".
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - cleanup logging.
 *                                                    add port to exception message.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add message buffer to write
 *                                                    logging only on failure.
 *    Achim Kraus (Bosch Software Innovations GmbH) - implement multicast support
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.DatagramSocketImpl;
import java.net.DatagramSocketImplFactory;
import java.net.InetAddress;
import java.net.PortUnreachableException;
import java.net.SocketException;
import java.net.SocketOptions;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.elements.runner.BufferedLoggingTestRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reliable "in process" message exchange implementation.
 * 
 * Uses internal queues instead of operation system IP stack. If port 0 is used
 * for the datagram socket, the implementation tries to assign a next unused
 * port in range {@link #AUTO_PORT_RANGE_MIN} to {@link #AUTO_PORT_RANGE_MAX}.
 * The full range is used before any free port is reused.
 * 
 * Though the communication is done "in process", the used "network interfaces"
 * are ignored. The message delivery is done only based on the port numbers. If
 * the datagram socket is bound to a any address, a received message will be
 * processed assuming being received with the same host interface information as
 * the sender of the message, so mostly "localhost" is assumed as receiving
 * interface. That also applies for multicast, the primary delivery is based on
 * the port number, the joined group addresses are only used to filter after
 * mapping the message to the port.
 * 
 * To log all exchanged message, use level DEBUG. If sending and receiving
 * should be distinguished, use level TRACE. If the messages should only be
 * written on failure, use INFO and the {@link BufferedLoggingTestRunner}. For
 * the test executed with maven, this is usually configured using the logging
 * properties ("module-directory/logback-test.xml").
 * 
 * Note: If not executed with maven, ensure, that the used "logback.xml" are
 * also matching your requirements, either by editing the global file
 * "JRE/lib/logback.xml" or by providing the property
 * "logback.configurationFile" with the filename of the logback configuration
 * file, usually "-Dlogback.configurationFile=logback-test.xml" should work for
 * the most californium modules.
 * 
 * Neither specific nor multi-network-interfaces are supported.
 */
public class DirectDatagramSocketImpl extends AbstractDatagramSocketImpl {

	/**
	 * Starting port number for automatic port binding.
	 */
	public static final int AUTO_PORT_RANGE_MIN = 8192;
	/**
	 * Last port number for automatic port binding.
	 */
	public static final int AUTO_PORT_RANGE_MAX = 65535;
	/**
	 * Number of ports for automatic port binding.
	 */
	public static final int AUTO_PORT_RANGE_SIZE = AUTO_PORT_RANGE_MAX - AUTO_PORT_RANGE_MIN + 1;

	private static final Logger LOGGER = LoggerFactory.getLogger(DirectDatagramSocketImpl.class.getName());

	/**
	 * Default factory, if {@code null} is provided for
	 * {@link #initialize(DatagramSocketImplFactory)}.
	 */
	private static final DatagramSocketImplFactory DEFAULT = new DirectDatagramSocketImplFactory();
	/**
	 * Map of sockets.
	 */
	private static final ConcurrentMap<Integer, List<DirectDatagramSocketImpl>> map = new ConcurrentHashMap<Integer, List<DirectDatagramSocketImpl>>();
	/**
	 * List of buffered logging messages.
	 */
	private static final ConcurrentLinkedQueue<String> logBuffer = new ConcurrentLinkedQueue<String>();
	/**
	 * Enable buffered logging.
	 */
	private static final AtomicBoolean enableLoggingBuffer = new AtomicBoolean();
	/**
	 * Time of last enabling buffered logging in system nanos.
	 */
	private static final AtomicLong loggingBufferStartTimeNanos = new AtomicLong();

	/**
	 * Initialization indicator.
	 * 
	 * @see #initialize(int, DatagramFormatter)
	 * @see #isEnabled()
	 */
	private static final AtomicReference<DatagramSocketImplFactory> init = new AtomicReference<DatagramSocketImplFactory>();

	/**
	 * Port counter for new port on bind.
	 */
	private static final AtomicInteger nextPort = new AtomicInteger(0);

	/**
	 * Initialization indicator.
	 * 
	 * @see #initialize(int, DatagramFormatter)
	 * @see #isEnabled()
	 */
	private static final AtomicReference<Setup> setup = new AtomicReference<Setup>();

	/**
	 * The inbound message queue.
	 */
	private final BlockingQueue<DatagramExchange> incomingQueue = new LinkedBlockingQueue<DatagramExchange>();

	/**
	 * Local address of socket.
	 */
	private InetAddress localAddress;

	/**
	 * Indicate, that the socket is closed.
	 * 
	 * @see #close()
	 */
	private boolean closed;

	/**
	 * Set of multicast group addresses.
	 * 
	 * @see #join(InetAddress)
	 * @see #leave(InetAddress)
	 */
	private final Set<InetAddress> multicast = new HashSet<>();

	/**
	 * Create instance of this socket implementation.
	 */
	private DirectDatagramSocketImpl() {
	}

	@Override
	protected void bind(int lport, InetAddress laddr) throws SocketException {
		LOGGER.debug("binding to port {}, address {}", lport, laddr);
		int port = bind(lport);
		synchronized (this) {
			this.localPort = port;
			this.localAddress = laddr;
		}
		setOption(SocketOptions.SO_BINDADDR, laddr);
	}

	@Override
	protected void close() {
		boolean isClosed;
		int port;
		InetAddress addr;
		synchronized (this) {
			isClosed = this.closed;
			port = this.localPort;
			addr = this.localAddress;
			this.closed = true;
		}
		LOGGER.debug("closing port {}, address {}", port, addr);
		if (!isClosed) {
			List<DirectDatagramSocketImpl> destinations = map.get(port);
			if (destinations == null) {
				LOGGER.info("cannot close unknown port {}, address {}", port, addr);
			} else if (!destinations.remove(this)) {
				LOGGER.info("cannot close unknown port {}, address {}", port, addr);
			} else if (destinations.isEmpty()) {
				map.remove(port, destinations);
			}
		}
	}

	@Override
	protected void receive(DatagramPacket destPacket) throws IOException {
		final int port;
		final InetAddress addr;
		synchronized (this) {
			port = this.localPort;
			addr = this.localAddress;
		}
		final int timeout = getSoTimeout();
		final Setup currentSetup = setup.get();
		final DatagramExchange exchange;
		try {
			if (0 < timeout) {
				exchange = incomingQueue.poll(timeout, TimeUnit.MILLISECONDS);
				if (null == exchange) {
					throw new SocketTimeoutException("no data available for port " + port);
				}
			} else {
				exchange = incomingQueue.take();
			}
			if (0 < currentSetup.delayInMs) {
				// intended for special test conditions
				Thread.sleep(currentSetup.delayInMs);
			}
		} catch (InterruptedException exception) {
			if (!incomingQueue.isEmpty()) {
				LOGGER.warn("interrupted while receiving!");
			}
			throw new InterruptedIOException(addr + ":" + port);
		}
		final boolean isClosed;
		synchronized (this) {
			isClosed = this.closed;
		}
		if (isClosed) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("socket already closed {}", exchange.format(currentSetup));
			}
			throw new SocketException("Socket " + addr + ":" + port + " already closed!");
		} else if (LOGGER.isTraceEnabled()) {
			LOGGER.trace("incoming {}", exchange.format(currentSetup));
		} else if (LOGGER.isDebugEnabled()) {
			LOGGER.debug(">> {}", exchange.format(currentSetup));
		} else if (LOGGER.isInfoEnabled() && enableLoggingBuffer.get()) {
			String line = exchange.format(currentSetup);
			long time = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - loggingBufferStartTimeNanos.get());
			logBuffer.offer(String.format("%04d: %s", time, line));
		}
		int receivedLength = exchange.data.length;
		int destPacketLength = destPacket.getLength();
		byte[] destPacketData = destPacket.getData();
		if (destPacketLength < receivedLength) {
			if (destPacketData.length > destPacketLength) {
				LOGGER.debug("increasing receive buffer from {} to full buffer capacity [{}]", destPacketLength,
						destPacketData.length);
				destPacketLength = destPacketData.length;
			}
			if (destPacketLength < receivedLength) {
				LOGGER.debug("truncating data [length: {}] to fit into receive buffer [size: {}]", receivedLength,
						destPacketLength);
				receivedLength = destPacketLength;
			}
		}
		destPacket.setLength(receivedLength);
		System.arraycopy(exchange.data, 0, destPacketData, 0, receivedLength);
		destPacket.setPort(exchange.sourcePort);
		destPacket.setAddress(exchange.sourceAddress);
	}

	@Override
	protected void send(DatagramPacket packet) throws IOException {
		final boolean isClosed;
		final int port;
		InetAddress local;
		synchronized (this) {
			isClosed = this.closed;
			port = this.localPort;
			local = this.localAddress;
		}
		final InetAddress destinationAddress = packet.getAddress();
		if (local.isAnyLocalAddress()) {
			// adjust any to destination host
			if (destinationAddress.isMulticastAddress()) {
				local = InetAddress.getLocalHost();
			} else {
				local = destinationAddress;
			}
		}
		final Setup currentSetup = setup.get();
		final DatagramExchange exchange = new DatagramExchange(local, port, packet);
		if (isClosed) {
			if (LOGGER.isWarnEnabled()) {
				LOGGER.warn("closed/packet dropped! {}", exchange.format(currentSetup));
			}
			throw new SocketException("socket is closed");
		}
		List<DirectDatagramSocketImpl> destinations = map.get(exchange.destinationPort);
		if (null == destinations) {
			String message = String.format("destination port %s not available!", exchange.destinationPort);
			if (LOGGER.isErrorEnabled()) {
				LOGGER.error("{} {}", message, exchange.format(currentSetup));
			}
			throw new PortUnreachableException(message);
		}
		// protect from parallel close()
		destinations = new ArrayList<>(destinations);
		if (destinations.isEmpty()) {
			String message = String.format("destination port %s not longer available!", exchange.destinationPort);
			if (LOGGER.isErrorEnabled()) {
				LOGGER.error("{} {}", message, exchange.format(currentSetup));
			}
			throw new PortUnreachableException(message);
		}
		for (DirectDatagramSocketImpl destinationSocket : destinations) {
			if (destinationSocket.matches(destinationAddress)) {
				if (!destinationSocket.incomingQueue.offer(exchange)) {
					if (LOGGER.isErrorEnabled()) {
						LOGGER.error("packet dropped! {}", exchange.format(currentSetup));
					}
					throw new PortUnreachableException("buffer exhausted");
				}
			}
		}
		if (LOGGER.isTraceEnabled()) {
			LOGGER.trace("outgoing {}", exchange.format(currentSetup));
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * This method must be declared in this actual implementation of
	 * {@link DatagramSocketImpl} to ensure, that {@code DatagramSocket} doesn't
	 * use the erroneous internal "old implementation mode".
	 */
	@Override
	protected int peekData(DatagramPacket p) throws IOException {
		throw new IOException("peekData(DatagramPacket) not supported!");
	}

	@Override
	protected void join(InetAddress inetaddr) throws IOException {
		synchronized (multicast) {
			multicast.add(inetaddr);
		}
	}

	@Override
	protected void leave(InetAddress inetaddr) throws IOException {
		synchronized (multicast) {
			multicast.remove(inetaddr);
		}
	}

	/**
	 * Datagram information for in process exchange.
	 */
	private static class DatagramExchange {

		/**
		 * Counter for datagram exchanges.
		 */
		private static final AtomicInteger ID = new AtomicInteger();

		/**
		 * Source address.
		 */
		public final InetAddress sourceAddress;
		/**
		 * Destination address.
		 */
		public final InetAddress destinationAddress;
		/**
		 * Source port.
		 */
		public final int sourcePort;
		/**
		 * Destination port.
		 */
		public final int destinationPort;
		/**
		 * ID of datagram exchange. Used for logging.
		 */
		public final int id;
		/**
		 * Data of datagram.
		 */
		public final byte[] data;

		/**
		 * Create datagram exchange.
		 * 
		 * @param address local address
		 * @param port local port
		 * @param packet datagram packet with destination and data
		 */
		public DatagramExchange(InetAddress address, int port, DatagramPacket packet) {
			this.sourceAddress = address;
			this.destinationAddress = packet.getAddress();
			this.sourcePort = port;
			this.destinationPort = packet.getPort();
			this.id = ID.incrementAndGet();
			this.data = new byte[packet.getLength()];
			System.arraycopy(packet.getData(), packet.getOffset(), data, 0, packet.getLength());
		}

		/**
		 * 
		 * @param currentSetup
		 * @return The formatted setup
		 */
		public String format(final Setup currentSetup) {
			long tid = Thread.currentThread().getId();
			String delay = "";
			String content = "";
			String destination = "";
			if (null != currentSetup) {
				if (null != currentSetup.formatter) {
					content = currentSetup.formatter.format(data);
				}
				if (0 < currentSetup.delayInMs) {
					delay = String.format("%dms", currentSetup.delayInMs);
				}
			}
			if (!sourceAddress.equals(destinationAddress)) {
				destination = destinationAddress.getHostAddress();
			}
			return java.text.MessageFormat.format("(E{0},T{1}) {2}:{3} ={4}=> {5}:{6} [{7}]", id, tid,
					sourceAddress.getHostAddress(), sourcePort, delay, destination, destinationPort, content);
		}
	}

	/**
	 * Bind socket to provided port. Register socket at {@link #map}.
	 * 
	 * @param lport provided local port. if 0, choose a free one from the
	 *            automatic range.
	 * @return local port
	 * @throws SocketException if provided port is not free or, if lport was -1,
	 *             no free port is available.
	 */
	private int bind(int lport) throws SocketException {
		List<DirectDatagramSocketImpl> newDestinations = new ArrayList<>();
		newDestinations.add(this);
		if (0 >= lport) {
			int count = AUTO_PORT_RANGE_SIZE;
			int port = AUTO_PORT_RANGE_MIN + nextPort.getAndIncrement() % AUTO_PORT_RANGE_SIZE;
			while (null != map.putIfAbsent(port, newDestinations)) {
				port = AUTO_PORT_RANGE_MIN + nextPort.getAndIncrement() % AUTO_PORT_RANGE_SIZE;
				if (0 >= --count) {
					throw new SocketException("No left free port!");
				}
			}
			LOGGER.debug("assigned port {}", port);
			return port;
		} else {
			List<DirectDatagramSocketImpl> destinations = map.putIfAbsent(lport, newDestinations);
			if (null != destinations) {
				boolean reuse = getReuseAddress();
				if (reuse) {
					for (DirectDatagramSocketImpl destination : destinations) {
						if (!destination.getReuseAddress()) {
							reuse = false;
							break;
						}
					}
				}
				if (reuse) {
					destinations.add(this);
					// put again, may be removed by a parallel close.
					map.putIfAbsent(lport, destinations);
				} else {
					throw new SocketException("Port " + lport + " already used!");
				}
			}
			return lport;
		}
	}

	/**
	 * Get socket timeout.
	 * 
	 * @return timeout in milliseconds. 0, doen't wait.
	 * @throws SocketException not used
	 */
	private int getSoTimeout() throws SocketException {
		Object option = getOption(SocketOptions.SO_TIMEOUT);
		if (option instanceof Integer) {
			return ((Integer) option).intValue();
		} else {
			return 0;
		}
	}

	/**
	 * Get socket reuse indicator.
	 * 
	 * @return {@code true} it the socket may be reused by other sockets (sharing the same port).
	 * @throws SocketException not used
	 */
	private boolean getReuseAddress() throws SocketException {
		Object option = getOption(SocketOptions.SO_REUSEADDR);
		if (option instanceof Boolean) {
			return ((Boolean) option).booleanValue();
		} else {
			return false;
		}
	}

	private boolean matches(InetAddress destination) {
		if (destination.isMulticastAddress()) {
			synchronized (multicast) {
				return multicast.contains(destination);
			}
		}
		return true;
	}

	/**
	 * Initialize DatagramSocketImplFactory.
	 * 
	 * @param factory factory for datagram socket. if null, {@link #DEFAULT}
	 *            factory is used, which creates
	 *            {@link DirectDatagramSocketImpl}.
	 * @return true, if initialization is executed, false, if it was already
	 *         executed.
	 * @see DatagramSocket#setDatagramSocketImplFactory(DatagramSocketImplFactory)
	 */
	public static boolean initialize(DatagramSocketImplFactory factory) {
		boolean calledFromTest = false;
		StackTraceElement[] stack = Thread.currentThread().getStackTrace();
		for (StackTraceElement call : stack) {
			if (call.getClassName().startsWith("junit.") || call.getClassName().startsWith("org.junit.")) {
				calledFromTest = true;
				break;
			}
		}
		if (!calledFromTest) {
			throw new IllegalAccessError("The DirectDatagramSocketImpl is intended to be used for tests only!");
		}
		if (null == factory) {
			factory = DEFAULT;
		}
		if (init.compareAndSet(null, factory)) {
			try {
				DatagramSocket.setDatagramSocketImplFactory(factory);
				return true;
			} catch (IOException ex) {
				LOGGER.error("DatagramSocketImplFactory", ex);
			}
		} else if (factory != init.get()) {
			LOGGER.warn("DatagramSocketImplFactory already set to {}", init.get().getClass());
		}
		return false;
	}

	/**
	 * Configure DatagramSocketImplFactory.
	 * 
	 * @param formatter datagram formatter.
	 * @param delayInMs delay processing of incoming message. Value in
	 *            milliseconds. 0 for no delay.
	 */
	public static void configure(final DatagramFormatter formatter, final int delayInMs) {
		setup.set(new Setup(formatter, delayInMs));
	}

	/**
	 * Check, if IP stack is initialized to use this DatagramSocketImpl.
	 * 
	 * @return true, stack uses this implementation, false otherwise.
	 * @see #initialize(DatagramSocketImplFactory)
	 */
	public static boolean isEnabled() {
		return null != init.get();
	}

	/**
	 * Check, if no open sockets exists.
	 * 
	 * @return {@code true}, if no sockets exists, {@code false}, otherwise
	 */
	public static boolean isEmpty() {
		return map.isEmpty();
	}

	/**
	 * Force sockets cleanup.
	 */
	public static void clearAll() {
		map.clear();
	}

	/**
	 * Clear all messages in the logging buffer. Enables buffered logging.
	 */
	public static void clearBufferLogging() {
		loggingBufferStartTimeNanos.set(System.nanoTime());
		logBuffer.clear();
		enableLoggingBuffer.set(true);
	}

	/**
	 * Flush all messages in the logging buffer. Disables buffered logging
	 * afterwards.
	 */
	public static void flushBufferLogging() {
		enableLoggingBuffer.set(false);
		int counter = 0;
		String message;
		while ((message = logBuffer.poll()) != null) {
			++counter;
			LOGGER.info(String.format("--%02d--> %s", counter, message));
		}
	}

	private static class Setup {

		/**
		 * Datagram formatter.
		 */
		public final DatagramFormatter formatter;

		/**
		 * Delay processing of incoming message. Value in milliseconds. 0 for no
		 * delay.
		 */
		public final int delayInMs;

		/**
		 * Create new setup.
		 * 
		 * @param formatter datagram formatter.
		 * @param delayInMs delay processing of incoming message. Value in
		 *            milliseconds. 0 for no delay.
		 */
		public Setup(final DatagramFormatter formatter, final int delayInMs) {
			this.formatter = formatter;
			this.delayInMs = delayInMs;
		}

	}

	/**
	 * Basic factory implementation using this {@link DirectDatagramSocketImpl}.
	 */
	public static class DirectDatagramSocketImplFactory implements DatagramSocketImplFactory {

		@Override
		public DatagramSocketImpl createDatagramSocketImpl() {
			return new DirectDatagramSocketImpl();
		}
	}
}
