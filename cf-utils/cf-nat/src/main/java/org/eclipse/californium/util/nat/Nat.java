/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation.
 *    Achim Kraus (Bosch Software Innovations GmbH) - add message dropping.
 ******************************************************************************/

package org.eclipse.californium.util.nat;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Simple test NAT.
 *
 * Supports interactive reassign of local mapped addresses.
 */
public class Nat {

	static {
		String property = System.getProperty("logback.configurationFile");
		if (property == null) {
			System.setProperty("logback.configurationFile", "logback-nat-config.xml");
		}
	}

	public static void main(String[] args) {
		String start = args.length > 0 ? args[0] : null;
		if (start != null) {
			String[] args2 = Arrays.copyOfRange(args, 1, args.length);
			if ("NAT".equals(start)) {
				execNAT(args2);
				return;
			} else if ("LB".equals(start)) {
				execLB(args2);
				return;
			}
		}
		System.out.println("\nCalifornium (Cf) NAT-Starter");
		System.out.println("(c) 2020, Bosch.IO GmbH and others");
		System.out.println();
		System.out.println("Usage: " + Nat.class.getSimpleName() + " (NAT|LB) ...");
		if (start != null) {
			System.out.println("   '" + start + "' is not supported!");
		}
		System.exit(-1);
	}

	public static void execNAT(String[] args) {
		if (args.length < 2 || args.length > 5) {
			System.out.println(
					"usage: [localinterface]:port destination:port [<messageDropping%>|-f<messageDropping%>|-b<messageDropping%>] [-s<sizeLimit>]");
			System.out.println(
					"       <messageDropping%>   : drops forward and backward messages with provided probability");
			System.out.println("       -f<messageDropping%> : drops forward messages with provided probability");
			System.out.println("       -b<messageDropping%> : drops backward messages with provided probability");
			System.out.println("       -s<sizeLimit>        : limit message size to provided value");
			System.out.println("       use -f and/or -b, if you want to test with different probabilities.");
			return;
		}
		NatUtil util = null;
		try {
			String line = null;
			int argsIndex = 0;
			InetSocketAddress proxyAddress = create(args[argsIndex], true);
			InetSocketAddress destinationAddress = create(args[++argsIndex], false);

			util = new NatUtil(proxyAddress, destinationAddress);
			if (args.length > ++argsIndex) {
				try {
					int limit = 0;
					String mode = "";
					String dropping = args[argsIndex];
					if (dropping.startsWith("-f") || dropping.startsWith("-b") || dropping.startsWith("-s")) {
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
					} else if (mode.equals("-s")) {
						limit = drops;
					} else {
						util.setMessageDropping(drops);
						System.out.println("dropping " + drops + "% of messages.");
					}
					if (args.length > ++argsIndex) {
						String mode2 = "";
						dropping = args[argsIndex];
						if (dropping.startsWith("-f") || dropping.startsWith("-b") || dropping.startsWith("-s")) {
							mode2 = dropping.substring(0, 2);
							dropping = dropping.substring(2);
						}
						if (mode.equals(mode2)) {
							System.out.println(args[argsIndex] + " ignored, would overwrite " + args[argsIndex - 1]);
						}
						drops = Integer.parseInt(dropping);
						if (mode2.equals("-f")) {
							util.setForwardMessageDropping(drops);
							System.out.println("dropping " + drops + "% of forward messages.");
						} else if (mode2.equals("-b")) {
							util.setBackwardMessageDropping(drops);
							System.out.println("dropping " + drops + "% of backward messages.");
						} else if (mode2.equals("-s")) {
							limit = drops;
						}
						if (args.length > ++argsIndex) {
							mode2 = "";
							dropping = args[argsIndex];
							if (dropping.startsWith("-s")) {
								mode2 = dropping.substring(0, 2);
								dropping = dropping.substring(2);
							}
							drops = Integer.parseInt(dropping);
							if (mode2.equals("-s")) {
								limit = drops;
							}
						}
					}
					if (limit > 0) {
						util.setMessageSizeLimit(100, limit, true);
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
				util.reassignNewLocalAddresses();
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (null != util) {
				util.stop();
			}
		}
	}

	public static void execLB(String[] args) {
		if (args.length < 3) {
			System.out.println(
					"usage: [localinterface]:port destination1:port1 destination2:port2 [destination3:port3 ...]");
			return;
		}
		NioNatUtil util = null;
		try {
			String line = null;
			int argsIndex = 0;
			InetSocketAddress proxyAddress = Nat.create(args[argsIndex++], true);
			List<InetSocketAddress> destinations = new ArrayList<>();
			for (; argsIndex < args.length; ++argsIndex) {
				InetSocketAddress destinationAddress = Nat.create(args[argsIndex], false);
				destinations.add(destinationAddress);
			}
			util = new NioNatUtil(proxyAddress, destinations);
			util.setNatTimeoutMillis(30 * 1000);

			BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
			while ((line = in.readLine()) != null) {
				if (line.equals("exit")) {
					util.stop();
					break;
				}
				int entries = util.getNumberOfEntries();
				int count = util.reassignDestinationAddresses();
				System.out.println("reassigned " + count + " destinations of " + entries + ".");
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (null != util) {
				util.stop();
			}
		}
	}

	public static InetSocketAddress create(String address, boolean any) throws URISyntaxException {
		if (address.startsWith(":")) {
			if (!any) {
				throw new URISyntaxException(address, "<any>: not allowed!");
			}
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
