/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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

import javax.xml.ws.Endpoint;

/**
 * The UDPConnector connects a server to the network using the UDP protocol. The
 * <code>UDPConnector</code> is bound to an {@link Endpoint} by a
 * {@link RawDataChannel}. An <code>Endpoint</code> sends messages encapsulated
 * within a {@link RawData} by calling the method {@link #send(RawData)} on the
 * connector. When the connector receives a message, it invokes
 * {@link RawDataChannel#receiveData(RawData)}. UDP broadcast is allowed.
 * // TODO: describe that we can make many threads
 */
public class UDPConnector implements Connector {

	public final static Logger LOGGER = Logger.getLogger(UDPConnector.class.toString());
	
	public static final int UNDEFINED = 0;
	
	private boolean running;
	
	private DatagramSocket socket;
	
	private final InetSocketAddress localAddr;
	
	private List<Thread> receiverThreads;
	private List<Thread> senderThreads;

	/** The queue of outgoing block (for sending). */
	private final BlockingQueue<RawData> outgoing; // Messages to send
	
	/** The receiver of incoming messages */
	private RawDataChannel receiver; // Receiver of messages
	
	private int receiveBuffer = UNDEFINED;
	private int sendBuffer = UNDEFINED;
	
	private int senderCount = 1;
	private int receiverCount = 1;
	
	private int receiverPacketSize = 2048;
	private boolean logPackets = false;
	
	public UDPConnector() {
		this(new InetSocketAddress(0));
	}
	
	public UDPConnector(InetSocketAddress address) {
		this.localAddr = address;
		this.running = false;
		
		this.outgoing = new LinkedBlockingQueue<RawData>();
	}
	
	@Override
	public synchronized void start() throws IOException {
		if (running) return;
		
		// if localAddr is null or port is 0, the system decides
		socket = new DatagramSocket(localAddr.getPort(), localAddr.getAddress());

		this.running = true;
		
		if (receiveBuffer != UNDEFINED)
			socket.setReceiveBufferSize(receiveBuffer);
		receiveBuffer = socket.getReceiveBufferSize();
		
		if (sendBuffer != UNDEFINED)
			socket.setSendBufferSize(sendBuffer);
		sendBuffer = socket.getSendBufferSize();
		
		// start receiver and sender threads
		LOGGER.config("UDP-connector starts "+senderCount+" sender threads and "+receiverCount+" receiver threads");
		
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
		
		LOGGER.config("UDP connector listening on "+socket.getLocalSocketAddress()+", recv buf = "+receiveBuffer+", send buf = "+sendBuffer
				+", recv packet size = "+receiverPacketSize+", log packets = "+logPackets);
	}

	@Override
	public synchronized void stop() {
		if (!running) return;
		this.running = false;
		// stop all threads
		if (senderThreads!= null)
			for (Thread t:senderThreads)
				t.interrupt();
		if (receiverThreads!= null)
			for (Thread t:receiverThreads)
				t.interrupt();
		outgoing.clear();
		if (socket != null)
			socket.close();
		socket = null;
	}

	@Override
	public synchronized void destroy() {
		stop();
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
	
	public InetSocketAddress getAddress() {
		if (socket == null) return localAddr;
		else return new InetSocketAddress(socket.getLocalAddress(), socket.getLocalPort());
	}
	
	private abstract class Worker extends Thread {

		/**
		 * Instantiates a new worker.
		 *
		 * @param name the name
		 */
		private Worker(String name) {
			super(name);
			setDaemon(true);
		}

		/* (non-Javadoc)
		 * @see java.lang.Thread#run()
		 */
		public void run() {
			LOGGER.fine("Starting "+getName());
			while (running) {
				try {
					work();
				} catch (Throwable t) {
					if (running)
						LOGGER.log(Level.WARNING, "Exception \""+t+"\" in thread " + getName()+": running="+running, t);
					else
						LOGGER.fine(getName()+" has successfully stopped");
				}
			}
		}

		/**
		 * @throws Exception the exception to be properly logged
		 */
		protected abstract void work() throws Exception;
	}
	
	private class Receiver extends Worker {
		
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
			if (logPackets)
				LOGGER.fine("Connector ("+socket.getLocalSocketAddress()+") received "+datagram.getLength()+" bytes from "+datagram.getAddress()+":"+datagram.getPort());

			byte[] bytes = Arrays.copyOfRange(datagram.getData(), datagram.getOffset(), datagram.getLength());
			RawData msg = new RawData(bytes);
			msg.setAddress(datagram.getAddress());
			msg.setPort(datagram.getPort());
			
			receiver.receiveData(msg);
		}
		
	}
	
	private class Sender extends Worker {
		
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
			if (logPackets)
				LOGGER.fine("Connector ("+socket.getLocalSocketAddress()+") sends "+datagram.getLength()+" bytes to "+datagram.getSocketAddress());
			socket.send(datagram);
		}
	}
	
	public void setReceiveBufferSize(int size) {
		this.receiveBuffer = size;
	}
	
	public int getReceiveBufferSize() {
		return receiveBuffer;
	}
	
	public void setSendBufferSize(int size) {
		this.sendBuffer = size;
	}
	
	public int getSendBufferSize() {
		return sendBuffer;
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
	
	public void setLogPackets(boolean b) {
		this.logPackets = b;
	}
	
	public boolean isLogPackets() {
		return logPackets;
	}
}
