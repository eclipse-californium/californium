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
 *    Stefan Jucker - DTLS implementation
 ******************************************************************************/
package org.eclipse.californium.scandium.examples;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.logging.Level;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.util.ScProperties;



public class ExampleDTLSClient {

	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.FINE);
	}

	public static final int DEFAULT_PORT = ScProperties.std.getInt("DEFAULT_PORT");
	
	private DTLSConnector dtlsConnector;
	
	public ExampleDTLSClient() {
		dtlsConnector = new DTLSConnector(new InetSocketAddress(0));
		dtlsConnector.setRawDataReceiver(new RawDataChannelImpl());
	}
	
	public void test() {
		try {
			dtlsConnector.start();
			dtlsConnector.send(new RawData("HELLO WORLD".getBytes(), InetAddress.getByName("localhost") , DEFAULT_PORT));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private class RawDataChannelImpl implements RawDataChannel {

		// @Override
		public void receiveData(final RawData raw) {
			
			System.out.println(new String(raw.getBytes()));
			
			dtlsConnector.close(new InetSocketAddress("localhost" , DEFAULT_PORT));
			
			// notify main thread to exit
			synchronized (ExampleDTLSClient.class) {
				ExampleDTLSClient.class.notify();
			}
		}
	}
	
	public static void main(String[] args) throws InterruptedException {
		
		ExampleDTLSClient client = new ExampleDTLSClient();
		client.test();
		
		// Connector threads run as daemons so wait in main thread until handshake is done
		synchronized (ExampleDTLSClient.class) {
			ExampleDTLSClient.class.wait();
		}
	}
}
