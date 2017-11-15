/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - clear thread-list on stop
 *                                                    log exception when stopping.
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix error stopping an connector,
 *                                                    when socket failed to open.
 *                                                    issue #345
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

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

	public final static Logger LOGGER = Logger.getLogger(UDPConnector.class.getName());
	
	public static final int UNDEFINED = 0;

	static final ThreadGroup ELEMENTS_THREAD_GROUP = new ThreadGroup("Californium/Elements"); //$NON-NLS-1$

	private volatile boolean running;

	private DatagramSocket socket;
	
	private final InetSocketAddress localAddr;
	
	private List<Thread> receiverThreads;
	private List<Thread> senderThreads;

	/** The outbound message queue. */
	private final BlockingQueue<RawData> outgoing;
	
	/** The receiver of incoming messages. */
	private RawDataChannel receiver;
	
	private int receiveBufferSize = UNDEFINED;
	private int sendBufferSize = UNDEFINED;
	
	private int senderCount = 1;
	private int receiverCount = 1;
	
	private int receiverPacketSize = 2048;
	
	/**
	 * Creates a connector on the wildcard address listening on an
	 * ephemeral port, i.e. a port chosen by the system.
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
	 * @param address the IP address and port, if <code>null</code>
	 * the connector is bound to an ephemeral port on the wildcard address
	 */
	public UDPConnector(InetSocketAddress address) {
		if (address == null) {
			this.localAddr = new InetSocketAddress(0);
		} else {
			this.localAddr = address;
		}
		this.running = false;
		
		//TODO: think about restricting the outbound queue's capacity
		this.outgoing = new LinkedBlockingQueue<RawData>();
	}
	
	@Override
	public synchronized void start() throws IOException {
		if (running) {
			return;
		}

		// if localAddr is null or port is 0, the system decides
		socket = new DatagramSocket(localAddr.getPort(), localAddr.getAddress());
		// running only, if the socket could be opened
		running = true;

		if (receiveBufferSize != UNDEFINED) {
			socket.setReceiveBufferSize(receiveBufferSize);
		}
		receiveBufferSize = socket.getReceiveBufferSize();
		
		if (sendBufferSize != UNDEFINED) {
			socket.setSendBufferSize(sendBufferSize);
		}
		sendBufferSize = socket.getSendBufferSize();
		
		// start receiver and sender threads
		LOGGER.log(Level.CONFIG, "UDPConnector starts up {0} sender threads and {1} receiver threads",
				new Object[]{senderCount, receiverCount});
		
		receiverThreads = new LinkedList<Thread>();
		for (int i=0;i<receiverCount;i++) {
			receiverThreads.add(new Receiver("UDP-Receiver-"+localAddr+"["+i+"]"));
		}
		
		senderThreads = new LinkedList<Thread>();
		for (int i=0;i<senderCount;i++) {
			senderThreads.add(new Sender("UDP-Sender-"+localAddr+"["+i+"]"));
		}

		for (Thread t:receiverThreads)
			t.start();
		for (Thread t:senderThreads)
			t.start();
		
		/*
		 * Java bug: sometimes, socket.getReceiveBufferSize() and
		 * socket.setSendBufferSize() block forever when called here. When
		 * called up there, it seems to work. This issue occurred in Java
		 * 1.7.0_09, Windows 7.
		 */
		
		if (LOGGER.isLoggable(Level.CONFIG)) {
			String startupMsg = new StringBuilder("UDPConnector listening on ")
				.append(socket.getLocalSocketAddress()).append(", recv buf = ")
				.append(receiveBufferSize).append(", send buf = ").append(sendBufferSize)
				.append(", recv packet size = ").append(receiverPacketSize).toString();
			LOGGER.log(Level.CONFIG, startupMsg);
		}
	}

	@Override
	public synchronized void stop() {
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
		outgoing.clear();
		
		String address = localAddr.toString();
		if (socket != null) {
			address = socket.getLocalSocketAddress().toString();
			socket.close();
			socket = null;
		}
		LOGGER.log(Level.CONFIG, "UDPConnector on [{0}] has stopped.", address);
	}

	@Override
	public void destroy() {
		stop();
	}

	@Override
	public void send(RawData msg) {
		if (msg == null) {
			throw new NullPointerException("Message must not be null");
		} else {
			outgoing.add(msg);
		}
	}

	@Override
	public void setRawDataReceiver(RawDataChannel receiver) {
		this.receiver = receiver;
	}
	
	public InetSocketAddress getAddress() {
		if (socket == null) return localAddr;
		else return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
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
			LOGGER.log(Level.FINE, "Starting network stage thread [{0}]", getName());
			while (true) {
				try {
					work();
					if (!running) {
						LOGGER.log(Level.FINE, "Network stage thread [{0}] was stopped successfully", getName());
						break;
					}
				} catch (Throwable t) {
					if (running) {
						LOGGER.log(Level.SEVERE, "Exception in network stage thread [" + getName() + "]:", t);
					} else {
						LOGGER.log(Level.FINE, "Network stage thread [{0}] was stopped successfully", getName());
						LOGGER.log(Level.FINER, "   stopped at:", t);
						break;
					}
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
			this.size = receiverPacketSize;
			this.datagram = new DatagramPacket(new byte[size], size);
		}
		
		protected void work() throws IOException {
			datagram.setLength(size);
			socket.receive(datagram);
			if (LOGGER.isLoggable(Level.FINER)) {
				LOGGER.log(Level.FINER, "UDPConnector ({0}) received {1} bytes from {2}:{3}",
						new Object[]{socket.getLocalSocketAddress(), datagram.getLength(),
							datagram.getAddress(), datagram.getPort()});
			}
			byte[] bytes = Arrays.copyOfRange(datagram.getData(), datagram.getOffset(), datagram.getLength());
			RawData msg = new RawData(bytes, datagram.getAddress(), datagram.getPort());

			receiver.receiveData(msg);
		}
		
	}
	
	private class Sender extends NetworkStageThread {
		
		private DatagramPacket datagram;
		
		private Sender(String name) {
			super(name);
			this.datagram = new DatagramPacket(new byte[0], 0);
		}
		
		protected void work() throws InterruptedException, IOException {
			RawData raw = outgoing.take(); // Blocking
			datagram.setData(raw.getBytes());
			datagram.setAddress(raw.getAddress());
			datagram.setPort(raw.getPort());
			if (LOGGER.isLoggable(Level.FINER)) {
				LOGGER.log(Level.FINER, "UDPConnector ({0}) sends {1} bytes to {2}:{3}",
						new Object[]{socket.getLocalSocketAddress(), datagram.getLength(),
							datagram.getAddress(), datagram.getPort()});
			}
			socket.send(datagram);
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
}
