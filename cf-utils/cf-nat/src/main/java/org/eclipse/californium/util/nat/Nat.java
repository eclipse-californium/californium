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
		if (args.length < 2) {
			System.out.println(
					"usage: :port destination:port [destination2:port2 ...] <other arguments>");
			System.out.println(
					"  or : localinterface:port [localinterface2:port2 ...] -- destination:port [destination2:port2 ...] <other arguments>");
			System.out.println(
					"       <other arguments> := [-r] [-x] [-tnat=<millis>] [-tln=<millis>] [-n=<maxNatEntries>]");
			System.out.println(
					"                            [-d=<messageDropping%>|[-f=<messageDropping%>][-b=<messageDropping%>]]");
			System.out.println(
					"                            [-s=<sizeLimit:probability%>]");
			System.out.println(
					"       -r                                           : enable reverse destination address update");
			System.out.println(
					"       -x                                           : enable DTLS filter.");
			System.out.println(
					"       -tnat=<milliseconds>                         : timeout for nat entries. Default " + NioNatUtil.NAT_TIMEOUT_MS + "[ms]");
			System.out.println(
					"       -tlb=<milliseconds>                          : timeout for destination entries. Default " + NioNatUtil.LB_TIMEOUT_MS + "[ms]");
			System.out.println(
					"       -n=<max-number-of-nat-entries>               : maximum number of NAT entries. Default " + NioNatUtil.MAXIMUM_NAT_ENTRIES);
			System.out.println(
					"       -d=<messageDropping%>                        : drops forward and backward messages with provided probability");
			System.out.println(
					"       -f=<messageDropping%>                        : drops forward messages with provided probability");
			System.out.println(
					"       -b=<messageDropping%>                        : drops backward messages with provided probability");
			System.out.println(
					"       -s=<sizeLimit:probability%>                  : limit message size to provided value");
			System.out.println();
			System.out.println("       use -f and/or -b, if you want to test with different probabilities.");
			return;
		}

		NioNatUtil util = null;
		try {
			String line = null;
			int argsIndex = 0;
			List<InetSocketAddress> proxyAddresses = new ArrayList<>();
			if (args[argsIndex].startsWith(":")) {
				proxyAddresses.add(createAnyAddress(args[argsIndex++]));
			} else {
				InetSocketAddress bind = createAddress("in ", args[argsIndex++]);
				proxyAddresses.add(bind);
				while (argsIndex < args.length && !args[argsIndex].equals("--")) {
					bind = createAddress("in ", args[argsIndex++]);
					proxyAddresses.add(bind);
				}
				++argsIndex;
				if (argsIndex >= args.length) {
					System.out.println("Missing destination!");
					return;
				}
			}
			InetSocketAddress destination = createAddress("out", args[argsIndex++]);
			util = new NioNatUtil(proxyAddresses, destination);
			char droppingMode = 0;
			while (argsIndex < args.length) {
				int value;
				int[] values;
				String arg = args[argsIndex++];
				if (arg.length() > 1 && arg.charAt(0) == '-') {
					char option = arg.charAt(1);
					switch (option) {
					case 'r':
						System.out.println("enable NAT reverse update.");
						util.setReverseNatUpdate(true);
						break;
					case 'x':
						System.out.println("enable DTLS filter.");
						util.setDtlsFilter(true);
						break;
					case 'd':
						if (droppingMode != 0) {
							System.out.println("dropping already provided!");
							break;
						}
						droppingMode = option;
						value = parse(2, arg)[0];
						util.setMessageDropping(value);
						System.out.println("dropping " + value + "% of messages.");
						break;
					case 'f':
						if (droppingMode == 'd') {
							System.out.println("dropping already provided!");
							break;
						}
						droppingMode = option;
						value = parse(2, arg)[0];
						util.setForwardMessageDropping(value);
						System.out.println("dropping " + value + "% of forward messages.");
						break;
					case 'b':
						if (droppingMode == 'd') {
							System.out.println("dropping already provided!");
							break;
						}
						droppingMode = option;
						value = parse(2, arg)[0];
						util.setBackwardMessageDropping(value);
						System.out.println("dropping " + value + "% of backwards messages.");
						break;
					case 's':
						values = parse(2, arg, 0, 100);
						util.setForwardMessageSizeLimit(values[1], values[0], true);
						System.out.println("size limit " + values[0] + " bytes, " + values[1] + " %.");
						break;
					case 'n':
						value = parse(2, arg)[0];
						util.setMaxiumNumberOfNatEntries(value);
						System.out.println("NAT max. entires " + value);
						break;
					case 't':
						if (arg.startsWith("-tnat")) {
							value = parse(5, arg)[0];
							util.setNatTimeoutMillis(value);
							System.out.println("NAT timeout " + value + "[ms].");
						} else if (arg.startsWith("-tlb")) {
							value = parse(4, arg)[0];
							util.setLoadBalancerTimeoutMillis(value);
							System.out.println("LoadBalancer timeout " + value + "[ms].");
						}
						break;
					default:
						System.out.println("option '" + arg + "' unknown!");
						break;
					}
				} else {
					InetSocketAddress destinationAddress = createAddress("out", arg);
					util.addDestination(destinationAddress);
				}
			}

			BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
			while ((line = in.readLine()) != null) {
				if (line.equals("exit") || line.equals("quit")) {
					System.out.println(">> " + line);
					break;
				} else if (line.equals("help") || line.equals("?")) {
					System.out.println("help or ? - print this help");
					System.out.println("info or <empty line> - list number of NAT entries and destinations");
					System.out.println("exit or quit - stop and exit");
					System.out.println("clear [n] - drop all NAT entries, or drop n NAT entries");
					System.out.println("reassign - reassign incoming addresses");
					System.out.println("rebalance - reassign outgoing addresses");
					System.out.println("add <host:port> - add new destination to load balancer");
					System.out.println("remove <host:port> - remove destination from load balancer");
					System.out.println("reverse (on|off) - enable/disable reverse address updates.");
				} else if (line.isEmpty() || line.equals("info")) {
					printInfo(util);
				} else if (line.equals("clear")) {
					int num = util.stopAllNatEntries();
					System.out.println(num + " - NAT entries dropped.");
				} else if (line.startsWith("clear ")) {
					try {
						int num = parse("clear ", line);
						num = util.stopNatEntries(num);
						System.out.println(num + " - NAT entries dropped.");
					} catch (NumberFormatException ex) {
					}
				} else if (line.equals("reassign")) {
					util.reassignNewLocalAddresses();
				} else if (line.equals("rebalance")) {
					util.addStaleDestinations();
					int entries = util.getNumberOfEntries();
					int count = util.reassignDestinationAddresses();
					System.out.println("reassigned " + count + " destinations of " + entries + ".");
				} else if (line.startsWith("remove ")) {
					try {
						InetSocketAddress dest = createDestinationAddress("remove ", line);
						if (util.removeDestination(dest)) {
							System.out.println(dest + " removed");
						}
					} catch (URISyntaxException e) {
						System.err.println(line);
						e.printStackTrace(System.err);
					}
				} else if (line.startsWith("add ")) {
					try {
						InetSocketAddress dest = createDestinationAddress("add ", line);
						if (util.addDestination(dest)) {
							System.out.println(dest + " added");
						}
					} catch (URISyntaxException e) {
						System.err.println(line);
						e.printStackTrace(System.err);
					}
				} else if (line.equals("reverse on")) {
					util.setReverseNatUpdate(true);
					printInfo(util);
				} else if (line.equals("reverse off")) {
					util.setReverseNatUpdate(false);
					printInfo(util);
				}
			}
			while (line == null) {
				Thread.sleep(100000);
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (null != util) {
				util.stop();
			}
		}
	}

	private static void printInfo(NioNatUtil util) {
		System.out.println(util.getNumberOfEntries() + " NAT entries, reverse address update "
				+ (util.useReverseNatUpdate() ? "enabled." : "disabled."));
		int stale = util.getNumberOfStaleDestinations();
		if (stale == 0) {
			System.out.println(util.getNumberOfDestinations() + " destinations.");
		} else {
			System.out.println(util.getNumberOfDestinations() + " destinations, " + stale + " stale destinations.");
		}
		List<NioNatUtil.NatAddress> destinations = util.getDestinations();
		for (NioNatUtil.NatAddress address : destinations) {
			System.out.println("Destination: " + address.name + ", usage: " + address.usageCounter());
		}
		destinations = util.getStaleDestinations();
		for (NioNatUtil.NatAddress address : destinations) {
			System.out.println("Stale      : " + address.name + ", usage: " + address.usageCounter() + ", last usage: "
					+ address.lastUsage() + "[s] " + address.getState());
		}
		destinations = util.getProbeDestinations();
		for (NioNatUtil.NatAddress address : destinations) {
			System.out.println("Probing    : " + address.name + ", usage: " + address.usageCounter() + ", last usage: "
					+ address.lastUsage() + "[s] " + address.getState());
		}
		destinations = util.getPendingDestinations();
		for (NioNatUtil.NatAddress address : destinations) {
			System.out.println("Pending    : " + address.name + ", usage: " + address.usageCounter() + ", last usage: "
					+ address.lastUsage() + "[s] " + address.getState());
		}
	}

	public static int parse(String head, String line) {
		return Integer.parseInt(line.substring(head.length()));
	}

	public static InetSocketAddress createDestinationAddress(String head, String line) throws URISyntaxException {
		return createAddress("out", line.substring(head.length()));
	}

	public static InetSocketAddress createAddress(String direction, String address) throws URISyntaxException {
		if (address.startsWith(":")) {
			throw new URISyntaxException(address, "<any>: not allowed!");
		} else {
			// use dummy schema
			URI uri = new URI("proxy://" + address);
			String host = uri.getHost();
			int port = uri.getPort();
			System.out.println(direction + ": " + address + " => " + host + ":" + port);
			InetSocketAddress result = new InetSocketAddress(host, port);
			result.getAddress();
			if (result.isUnresolved()) {
				System.err.println("Address: " + address + " is unresolved!");
				return null;
			}
			return result;
		}
	}

	public static InetSocketAddress createAnyAddress(String address) throws URISyntaxException {
		if (address.startsWith(":")) {
			// port only => any local address
			int port = Integer.parseInt(address.substring(1));
			System.out.println("in : " + address + " => <any>:" + port);
			return new InetSocketAddress(port);
		} else {
			throw new IllegalArgumentException(address + ", <interface>:<port> not allowed!");
		}
	}

	/**
	 * Parse argument.
	 * 
	 * @param pos position of value in argument
	 * @param arg argument
	 * @param defs default values
	 * @return parsed values.
	 * @since 2.5
	 */
	public static int[] parse(int pos, String arg, int... defs) {
		int index = 0;
		try {
			if (arg.charAt(pos) == '=') {
				++pos;
			}
			String value = pos == 0 ? arg : arg.substring(pos);
			String[] values = value.split(":");
			int len = Math.max(values.length, defs.length);
			int[] results = new int[len];
			for (; index < len; ++index) {
				if (index < values.length) {
					results[index] = Integer.parseInt(values[index]);
				} else {
					results[index] = defs[index];
				}
			}
			return results;
		} catch (NumberFormatException e) {
			throw new NumberFormatException(arg + "[" + index + "]: " + e.getMessage());
		}
	}
}
