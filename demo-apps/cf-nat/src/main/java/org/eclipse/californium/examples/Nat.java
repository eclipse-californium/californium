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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 ******************************************************************************/

package org.eclipse.californium.examples;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Simple test NAT.
 *
 * Supports interactive reassign of local mapped addresses.
 */
public class Nat {

	public static void main(String[] args) {
		if (args.length != 2) {
			System.out.println("usage: [localinterface]:port destination:port");
			return;
		}
		NatUtil util = null;
		try {
			InetSocketAddress proxyAddress = create(args[0]);
			InetSocketAddress destinationAddress = create(args[1]);
			String line = null;
			util = new NatUtil(proxyAddress, destinationAddress);
			BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
			while ((line = in.readLine()) != null) {
				if (line.equals("exit")) {
					util.stop();
					break;
				}
				util.reassignLocalAddresses();
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (null != util) {
				util.stop();
			}
		}
	}

	private static InetSocketAddress create(String address) throws URISyntaxException {
		if (address.startsWith(":")) {
			// port only => any local address
			int port = Integer.parseInt(address.substring(1));
			System.out.println(address + " => <any>:" + port);
			return new InetSocketAddress(port);
		} else {
			// use dummy schema
			URI uri = new URI("proxy://" + address);
			String host = uri.getHost();
			int port = uri.getPort();
			System.out.println(address + " => " + host + ":" + port);
			return new InetSocketAddress(host, port);
		}
	}
}
