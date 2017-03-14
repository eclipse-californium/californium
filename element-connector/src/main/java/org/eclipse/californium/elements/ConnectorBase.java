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
 ******************************************************************************/
package org.eclipse.californium.elements;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * ConnectorBase is a partial implementation of a {@link Connector}. It connects
 * a server to a network interface and a port. ConnectorBase contains two
 * separate threads for sending and receiving. The receiver thread constantly
 * calls #receiveNext() which is supposed to listen on a socket until a datagram
 * arrives and forward it to the {@link RawDataChannel}. The sender thread
 * constantly calls #sendNext() which is supposed to wait on the outgoing queue
 * for a {@link RawData} message to send. Both #sendNext() and #receiveNext()
 * are expected to be blocking.
 * 
 * @deprecated Use {@code UDPConnector} as a template for implementing a custom
 *             {@code Connector}.
 */
@Deprecated
public abstract class ConnectorBase implements Connector {

	/** The Logger. */
	private final static Logger LOGGER = Logger.getLogger(ConnectorBase.class.toString());

	/** The local address. */
	private final InetSocketAddress localAddr;

	/** The thread that receives messages */
	private Thread receiverThread;

	/** The thread that sends messages */
	private Thread senderThread;

	/** The queue of outgoing block (for sending). */
	private final BlockingQueue<RawData> outgoing; // Messages to send

	/** The receiver of incoming messages */
	private RawDataChannel receiver; // Receiver of messages

	/** Indicates whether the connector has started and not stopped yet */
	private boolean running;

	/**
	 * Instantiates a new connector base.
	 *
	 * @param address the address to listen to
	 */
	public ConnectorBase(InetSocketAddress address) {
		if (address == null)
			throw new NullPointerException();
		this.localAddr = address;

		// Optionally define maximal capacity
		this.outgoing = new LinkedBlockingQueue<RawData>();
	}

	public InetSocketAddress getAddress() {
		return localAddr;
	}

	/**
	 * Gets the name of the connector, e.g. the transport protocol used such as
	 * UDP or DTlS.
	 *
	 * @return the name
	 */
	public abstract String getName();

	/**
	 * Receives data from the socket queue.
	 * 
	 * @throws Exception any exceptions that should be properly logged
	 * @return the received raw data with metadata
	 */
	protected abstract RawData receiveNext() throws Exception;

	/**
	 * Sends data over the socket.
	 * 
	 * @param raw the raw data with metadata
	 * @throws Exception any exception that should be properly logged
	 */
	protected abstract void sendNext(RawData raw) throws Exception;

	/**
	 * Gets the receiver thread count.
	 *
	 * @return the receiver thread count
	 */
	protected int getReceiverThreadCount() {
		return 1;
	}

	/**
	 * Gets the sender thread count.
	 *
	 * @return the sender thread count
	 */
	protected int getSenderThreadCount() {
		return 1;
	}

	/**
	 * Receive next message from network and forward them to the receiver.
	 *
	 * @throws Exception any exception that occurs
	 */
	private void receiveNextMessageFromNetwork() throws Exception {
		RawData raw = receiveNext();
		if (raw != null)
			receiver.receiveData(raw);
	}

	/**
	 * Get the next message from the outgoing queue and send it over the
	 * network.
	 * 
	 * @throws Exception the exception
	 */
	private void sendNextMessageOverNetwork() throws Exception {
		RawData raw = outgoing.take(); // Blocking
		if (raw == null)
			throw new NullPointerException();
		sendNext(raw);
	}

	@Override
	public synchronized void start() throws IOException {
		if (running)
			return;
		running = true;

		int senderCount = getSenderThreadCount();
		int receiverCount = getReceiverThreadCount();
		LOGGER.config(getName() + "-connector starts " + senderCount + " sender threads and " + receiverCount
				+ " receiver threads");

		senderThread = new Worker(getName() + "-Sender-" + localAddr) {

			public void work() throws Exception {
				sendNextMessageOverNetwork();
			}
		};

		receiverThread = new Worker(getName() + "-Receiver-" + localAddr) {

			public void work() throws Exception {
				receiveNextMessageFromNetwork();
			}
		};

		receiverThread.start();
		senderThread.start();
	}

	@Override
	public synchronized void stop() {
		if (!running)
			return;
		running = false;
		senderThread.interrupt();
		receiverThread.interrupt();
		outgoing.clear();
	}

	/**
	 * Stops the connector and cleans up any leftovers. A destroyed connector
	 * cannot be expected to be able to start again. Note that this does not
	 * call stop() but the subclass has to do that if required.
	 */
	@Override
	public synchronized void destroy() {
	}

	@Override
	public void send(RawData msg) {
		if (msg == null)
			throw new NullPointerException();
		outgoing.add(msg);
	}

	@Override
	public void setRawDataReceiver(RawDataChannel receiver) {
		this.receiver = receiver;
	}

	/**
	 * Abstract worker thread that wraps calls to
	 * {@link ConnectorBase#getNextOutgoing()} and
	 * {@link ConnectorBase#receiveNext()}. Therefore, exceptions do not crash
	 * the threads and will be properly logged.
	 */
	private abstract class Worker extends Thread {

		/**
		 * Instantiates a new worker.
		 *
		 * @param name the name, e.g., of the transport protocol
		 */
		private Worker(String name) {
			super(name);
			setDaemon(true);
		}

		public void run() {
			try {
				LOGGER.fine("Starting thread " + getName());
				while (running) {
					try {
						work();
					} catch (Throwable t) {
						if (running)
							LOGGER.log(Level.WARNING, "Exception \"" + t + "\" in thread " + getName(), t);
						else
							LOGGER.fine("Exception \"" + t + "\" stopped thread " + getName());
					}
				}
			} finally {
				LOGGER.fine("Thread " + getName() + " has terminated");
			}
		}

		/**
		 * Override this method and call {@link ConnectorBase#receiveNext()} or
		 * {@link ConnectorBase#sendNext()}.
		 * 
		 * @throws Exception the exception to be properly logged
		 */
		protected abstract void work() throws Exception;
	}

	/**
	 * Gets the local address this connector is listening to.
	 *
	 * @return the local address
	 */
	public InetSocketAddress getLocalAddr() {
		return localAddr;
	}

	/**
	 * Gets the receiver.
	 *
	 * @return the receiver
	 */
	public RawDataChannel getReceiver() {
		return receiver;
	}

	/**
	 * Sets the receiver for incoming messages.
	 *
	 * @param receiver the new receiver
	 */
	public void setReceiver(RawDataChannel receiver) {
		this.receiver = receiver;
	}

	/**
	 * Checks the connector has started but not stopped yet.
	 *
	 * @return true, if is running
	 */
	public boolean isRunning() {
		return running;
	}
}
