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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add message dropping.
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
		if (args.length < 2 || args.length > 4) {
			System.out.println(
					"usage: [localinterface]:port destination:port [<messageDropping%>|-f<messageDropping%>|-b<messageDropping%>]");
			System.out.println(
					"       <messageDropping%>   : drops forward and backward messages with provided probability");
			System.out.println("       -f<messageDropping%> : drops forward messages with provided probability");
			System.out.println("       -b<messageDropping%> : drops backward messages with provided probability");
			System.out.println("       use -f and/or -b, if you want to test with different probabilities.");
			return;
		}
		NatUtil util = null;
		try {
			String line = null;
			InetSocketAddress proxyAddress = create(args[0]);
			InetSocketAddress destinationAddress = create(args[1]);

			util = new NatUtil(proxyAddress, destinationAddress);
			if (args.length > 2) {
				try {
					String mode = "";
					String dropping = args[2];
					if (dropping.startsWith("-f") || dropping.startsWith("-b")) {
						mode = dropping.substring(0, 2);
						dropping = dropping.substring(2);
					}
					int drops = Integer.parseInt(dropping);
					if (mode.equals("-f")) {
						util.setForwardMessageDropping(drops);
						System.out.println("dropping " + drops + "% of forward messages.");
					} else if (mode.equals("-b")) {
						util.setBackwardMessageDropping(drops);
						System.out.println("dropping " + drops + "% of backward messages.");
					} else {
						util.setMessageDropping(drops);
						System.out.println("dropping " + drops + "% of messages.");
					}
					if (args.length > 3) {
						String mode2 = "";
						dropping = args[3];
						if (dropping.startsWith("-f") || dropping.startsWith("-b")) {
							mode2 = dropping.substring(0, 2);
							dropping = dropping.substring(2);
						}
						if (mode.equals(mode2)) {
							System.out.println(args[3] + " ignored, would overwrite " + args[2]);
						}
						drops = Integer.parseInt(dropping);
						if (mode2.equals("-f")) {
							util.setForwardMessageDropping(drops);
							System.out.println("dropping " + drops + "% of forward messages.");
						} else if (mode2.equals("-b")) {
							util.setBackwardMessageDropping(drops);
							System.out.println("dropping " + drops + "% of backward messages.");
						}
					}
				} catch (NumberFormatException e) {
					System.err.println("drops% " + args[2] + " is no valid number!");
				}
			}
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
