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
import java.io.UnsupportedEncodingException;
import java.net.InetSocketAddress;
import java.util.logging.Level;

import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.ScandiumLogger;
import org.eclipse.californium.scandium.dtls.pskstore.InMemoryPskStore;
import org.eclipse.californium.scandium.util.ScProperties;



public class ExampleDTLSServer {

	static {
		ScandiumLogger.initialize();
		ScandiumLogger.setLevel(Level.ALL);
	}

	public static final int DEFAULT_PORT = ScProperties.std.getInt("DEFAULT_PORT");
	
	private Connector dtlsConnector;
	
	public ExampleDTLSServer() {
	    InMemoryPskStore pskStore = new InMemoryPskStore();
	    try {
            // put in the PSK store the default identity/psk for tinydtls tests
	        pskStore.setKey("Client_identity", "secretPSK".getBytes("US-ASCII"));
        } catch (UnsupportedEncodingException e) {
           throw new IllegalStateException("no US-ASCII codec in your JVM",e); 
        }
	    
		dtlsConnector = new DTLSConnector(new InetSocketAddress(DEFAULT_PORT),pskStore);
		
		dtlsConnector.setRawDataReceiver(new RawDataChannelImpl(dtlsConnector));
	}
	
	public void start() {
		try {
			dtlsConnector.start();
		} catch (IOException e) {
			throw new IllegalStateException("Unexpected error starting the DTLS UDP server",e);
		}
	}
	
	private class RawDataChannelImpl implements RawDataChannel {
		
		private Connector connector;
		
		public RawDataChannelImpl(Connector con) {
			this.connector = con;
		}

		// @Override
		public void receiveData(final RawData raw) {
			if (raw.getAddress() == null)
				throw new NullPointerException();
			if (raw.getPort() == 0)
				throw new NullPointerException();
			
			System.out.println(new String(raw.getBytes()));
			connector.send(new RawData("ACK".getBytes(), raw.getAddress(), raw.getPort()));
		}
	}
	
	public static void main(String[] args) {
		
		ExampleDTLSServer server = new ExampleDTLSServer();
		server.start();
		
		try {
			System.in.read();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
}
