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
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.DatagramSocketImpl;
import java.net.DatagramSocketImplFactory;
import java.net.InetAddress;
import java.net.PortUnreachableException;
import java.net.SocketException;
import java.net.SocketOptions;
import java.net.SocketTimeoutException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Reliable "in process" message exchange implementation.
 * 
 * Uses internal queues instead of operation system IP stack. If port 0 is used
 * for the datagram socket, the implementation tries to assign a next unused
 * port in range {@link #AUTO_PORT_RANGE_MIN} to {@link #AUTO_PORT_RANGE_MAX}.
 * The full range is used before any free port is reused.
 * 
 * Currently neither multicast nor specific/multi network interfaces are
 * supported.
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

	/**
	 * Maximum number of kept exchanges, if logging FINE/FINER is disabled.
	 */
	private static final int MAX_KEPT_EXCHANGES = 200;

	private static final Logger LOGGER = Logger.getLogger(DirectDatagramSocketImpl.class.getName());

	/**
	 * Default factory, if {@code null} is provided for
	 * {@link #initialize(DatagramSocketImplFactory)}.
	 */
	private static final DatagramSocketImplFactory DEFAULT = new DirectDatagramSocketImplFactory();

	/**
	 * List for exchanges, if logging FINE/FINER is disabled.
	 * 
	 * Limited to maximum {@link #MAX_KEPT_EXCHANGES} exchanges.
	 * 
	 * @see #clearConditionalLog()
	 * @see #conditionalLog()
	 * @see #keepForConditionalLogging(DatagramExchange)
	 */
	private static final List<DatagramExchange> exchangesForConditionalLogging = new LinkedList<DatagramExchange>();

	/**
	 * Map of sockets.
	 */
	private static final ConcurrentMap<Integer, DirectDatagramSocketImpl> map = new ConcurrentHashMap<Integer, DirectDatagramSocketImpl>();

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
	 * Create instance of this socket implementation.
	 */
	private DirectDatagramSocketImpl() {
	}

	@Override
	protected void bind(int lport, InetAddress laddr) throws SocketException {
		LOGGER.log(Level.FINE, "binding to port {0}, address {1}", new Object[] { lport, laddr });
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
		LOGGER.log(Level.FINE, "closing port {0}, address {1}", new Object[] { port, addr });
		if (!isClosed) {
			if (!map.remove(port, this)) {
				LOGGER.log(Level.INFO, "cannot close unknown port {0}, address {1}", new Object[] { port, addr });
			}
		}
	}

	@Override
	protected void receive(DatagramPacket destPacket) throws IOException {
		int port;
		InetAddress addr;
		synchronized (this) {
			port = this.localPort;
			addr = this.localAddress;
		}
		try {
			final int timeout = getSoTimeout();
			final DatagramExchange exchange;
			final Setup currentSetup = setup.get();
			if (0 < timeout) {
				exchange = incomingQueue.poll(timeout, TimeUnit.MILLISECONDS);
				if (null == exchange) {
					throw new SocketTimeoutException("no data available");
				}
			} else {
				exchange = incomingQueue.take();
			}
			if (0 < currentSetup.delayInMs) {
				// intended for special test conditions
				Thread.sleep(currentSetup.delayInMs);
			}
			boolean isClosed;
			synchronized (this) {
				isClosed = this.closed;
				port = this.localPort;
				addr = this.localAddress;
			}
			if (isClosed) {
				LOGGER.log(Level.FINE, "socket already closed {0}", exchange.format(currentSetup));
				throw new SocketException("Socket " + addr + ":" + port + " closed!");
			} else if (LOGGER.isLoggable(Level.FINER)) {
				LOGGER.log(Level.FINER, "incoming {0}", exchange.format(currentSetup));
			} else if (LOGGER.isLoggable(Level.INFO)) {
				LOGGER.log(Level.INFO, "{0}", exchange.format(currentSetup));
			} else if (LOGGER.isLoggable(Level.INFO)) {
				keepForConditionalLogging(exchange);
			}
			int receivedLength = exchange.data.length;
			int destPacketLength = destPacket.getLength();
			byte[] destPacketData = destPacket.getData();
			if (destPacketLength < receivedLength) {
				if (destPacketData.length > destPacketLength) {
					LOGGER.log(Level.FINE, "increasing receive buffer from {0} to full buffer capacity [{1}]",
							new Object[] { destPacketLength, destPacketData.length });
					destPacketLength = destPacketData.length;
				}
				if (destPacketLength < receivedLength) {
					LOGGER.log(Level.FINE, "truncating data [length: {0}] to fit into receive buffer [size: {1}]",
							new Object[] { receivedLength, destPacketLength });
					receivedLength = destPacketLength;
				}
			}
			destPacket.setLength(receivedLength);
			System.arraycopy(exchange.data, 0, destPacketData, 0, receivedLength);
			destPacket.setPort(exchange.sourcePort);
			destPacket.setAddress(exchange.sourceAddress);
		} catch (InterruptedException exception) {
			if (!incomingQueue.isEmpty()) {
				LOGGER.log(Level.WARNING, "interrupted while receiving!");
			}
			throw new SocketException(exception.getMessage() + addr + ":" + port);
		}
	}

	@Override
	protected void send(DatagramPacket packet) throws IOException {
		boolean isClosed;
		int port;
		InetAddress local;
		synchronized (this) {
			isClosed = this.closed;
			port = this.localPort;
			local = this.localAddress;
		}
		if (local.isAnyLocalAddress()) {
			// adjust any to destination host
			local = packet.getAddress();
		}
		Setup currentSetup = setup.get();
		DatagramExchange exchange = new DatagramExchange(local, port, packet);
		DirectDatagramSocketImpl destination = map.get(exchange.destinationPort);
		if (null == destination) {
			LOGGER.log(Level.SEVERE, "destination (port {0}) not available! {1}",
					new Object[] { exchange.destinationPort, exchange.format(currentSetup) });
			throw new PortUnreachableException("destination not available");
		} else if (isClosed) {
			LOGGER.log(Level.WARNING, "closed/packet dropped! {0}", exchange.format(currentSetup));
			throw new SocketException("socket is closed");
		} else if (!destination.incomingQueue.offer(exchange)) {
			LOGGER.log(Level.SEVERE, "packet dropped! {0}", exchange.format(currentSetup));
			throw new PortUnreachableException("buffer exhausted");
		} else if (LOGGER.isLoggable(Level.FINER)) {
			LOGGER.log(Level.FINER, "outgoing {0}", exchange.format(currentSetup));
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
			return java.text.MessageFormat.format("(E{0},T{1}) {2}:{3} ={4}=> {5}:{6} [{7}]", new Object[] { id, tid,
					sourceAddress.getHostAddress(), sourcePort, delay, destination, destinationPort, content });
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
		if (0 >= lport) {
			int count = AUTO_PORT_RANGE_SIZE;
			int port = AUTO_PORT_RANGE_MIN + nextPort.getAndIncrement() % AUTO_PORT_RANGE_SIZE;
			while (null != map.putIfAbsent(port, this)) {
				port = AUTO_PORT_RANGE_MIN + nextPort.getAndIncrement() % AUTO_PORT_RANGE_SIZE;
				if (0 >= --count) {
					throw new SocketException("No left free port!");
				}
			}
			LOGGER.log(Level.FINE, "assigned port {0}", port);
			return port;
		} else {
			if (null != map.putIfAbsent(lport, this)) {
				throw new SocketException("Port " + lport + " already used!");
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
				LOGGER.log(Level.SEVERE, "DatagramSocketImplFactory", ex);
			}
		} else if (factory != init.get()) {
			LOGGER.log(Level.WARNING, "DatagramSocketImplFactory already set to {0}", init.get().getClass());
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
	 * Clear exchanges kept for conditional logging.
	 * 
	 * @see #exchangesForConditionalLogging
	 */
	public static void clearConditionalLog() {
		synchronized (exchangesForConditionalLogging) {
			exchangesForConditionalLogging.clear();
		}
	}

	/**
	 * Log exchanges kept for conditional logging.
	 * 
	 * @see #exchangesForConditionalLogging
	 */
	public static void conditionalLog() {
		final Setup currentSetup = setup.get();
		DatagramExchange list[];
		synchronized (exchangesForConditionalLogging) {
			list = exchangesForConditionalLogging.toArray(new DatagramExchange[exchangesForConditionalLogging.size()]);
			exchangesForConditionalLogging.clear();
		}
		for (DatagramExchange exchange : list) {
			LOGGER.log(Level.INFO, ">> {0}", exchange.format(currentSetup));
		}
	}

	/**
	 * Keep exchange for conditional logging.
	 * 
	 * @param exchange exchange to be kept
	 */
	private static void keepForConditionalLogging(DatagramExchange exchange) {
		synchronized (exchangesForConditionalLogging) {
			if (MAX_KEPT_EXCHANGES <= exchangesForConditionalLogging.size()) {
				exchangesForConditionalLogging.remove(0);
			}
			exchangesForConditionalLogging.add(exchange);
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
