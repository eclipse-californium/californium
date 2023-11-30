/*******************************************************************************
 * Copyright (c) 2021 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.unixhealth;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.NotForAndroid;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Net socket health.
 * 
 * Socket's message drop statistic from OS. Currently only supports unix and
 * UDP.
 * 
 * A external {@link SimpleCounterStatistic} (managed by a different
 * {@link CounterStatisticManager}, e.g. DtlsHealthLogger) may be provided along
 * with the local socket address to be added to the statistics. On
 * {@link #read()} the current values are then not only transferred to this
 * statistics, the external ones are also updated.
 * 
 * @since 3.1
 */
@NotForAndroid
public class NetSocketHealthLogger extends CounterStatisticManager {

	/**
	 * The logger.
	 * 
	 * @deprecated scope will change to private.
	 */
	@Deprecated
	protected static final Logger LOGGER = LoggerFactory.getLogger(NetSocketHealthLogger.class);

	/**
	 * IPv4 file to read.
	 */
	private static final File ipv4File = new File("/proc/net/udp");
	/**
	 * IPv6 file to read.
	 */
	private static final File ipv6File = new File("/proc/net/udp6");
	/**
	 * Header for IPv4 addresses in udp6 table.
	 */
	private static final String IPV4_HEADER = "0000000000000000FFFF0000";
	/**
	 * Header for IPv4 any addresses in udp6 table.
	 */
	private static final String IPV4_ANY_HEADER = "000000000000000000000000";
	/**
	 * IPv4 any address.
	 */
	private static final String IPV4_ANY = "00000000:";

	/**
	 * Parser for lines.
	 */
	private final Parser parser;
	/**
	 * Map of external statistics.
	 * 
	 * {@link SimpleCounterStatistic} managed by a different
	 * {@link CounterStatisticManager}.
	 */
	private final ConcurrentMap<String, SimpleCounterStatistic> externalStatistics = new ConcurrentHashMap<>();

	/**
	 * Create passive net socket health.
	 * 
	 * {@link #dump()} is intended to be called externally.
	 * 
	 * @param tag logging tag
	 */
	public NetSocketHealthLogger(String tag) {
		super(tag);
		this.parser = new UdpParser();
	}

	/**
	 * Add local address to statistics.
	 * 
	 * @param local local address
	 * @param externalStatistic related external statistic
	 * @return {@code true}, if address was added to the statistics,
	 *         {@code false}, otherwise.
	 */
	public boolean add(InetSocketAddress local, SimpleCounterStatistic externalStatistic) {
		UdpAddParser parser = new UdpAddParser(local, externalStatistic);
		read(ipv4File, parser);
		if (!parser.added()) {
			read(ipv6File, parser);
		}
		return parser.added();
	}

	/**
	 * Remove local address from statistics.
	 * 
	 * @param local local address
	 */
	public void remove(InetSocketAddress local) {
		String localIP = getAddress(local);
		removeByKey(localIP);
		if (localIP.length() <= 13) {
			localIP = expandAddressForIpv6(localIP);
			removeByKey(localIP);
		}
	}

	@Override
	protected void removeByKey(String key) {
		super.removeByKey(key);
		externalStatistics.remove(key);
	}

	@Override
	public boolean isEnabled() {
		return LOGGER.isInfoEnabled() && (ipv4File.canRead() || ipv6File.canRead());
	}

	@Override
	public void dump() {
		if (isEnabled()) {
			read();
			if (LOGGER.isDebugEnabled()) {
				String eol = StringUtil.lineSeparator();
				String head = "   " + tag;
				StringBuilder log = new StringBuilder();
				log.append(tag).append("socket drops:").append(eol);
				for (String key : getKeys()) {
					SimpleCounterStatistic statistic = getByKey(key);
					log.append(head).append(statistic).append(eol);
				}
				log.setLength(log.length() - eol.length());
				LOGGER.debug("{}", log);
			}
			transferCounter();
		}
	}

	/**
	 * Read dropped messages for sockets.
	 * 
	 * Update also the related external {@link SimpleCounterStatistic}s.
	 * 
	 * @return {@code true}, if statistics are updated, {@code false}, if not.
	 */
	public boolean read() {
		boolean read = false;
		if (ipv4File.canRead() || ipv6File.canRead()) {
			try {
				if (!getKeys().isEmpty()) {
					read = true;
					read(ipv4File, parser);
					read(ipv6File, parser);
				}
			} catch (Throwable e) {
				LOGGER.error("{}", tag, e);
			}
		}
		return read;
	}

	/**
	 * Read file and {@link Parser#parse(String)} the read lines.
	 * 
	 * @param file file to read
	 * @param parser parser to parse the lines
	 */
	private void read(File file, Parser parser) {
		if (file.canRead()) {
			try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
				String line;
				parser.start();
				while ((line = reader.readLine()) != null) {
					if (parser.parse(line.trim())) {
						break;
					}
				}
			} catch (FileNotFoundException e) {
				LOGGER.warn("{} missing!", file.getAbsolutePath(), e);
			} catch (IOException e) {
				LOGGER.warn("{} error!", file.getAbsolutePath(), e);
			}
		}
	}

	/**
	 * Parser for single lines of "/proc/net/udp" and "/proc/net/udp6".
	 */
	private interface Parser {

		/**
		 * Start parsing before the first line of a file.
		 */
		void start();

		/**
		 * Parse read line.
		 * 
		 * @param line read line
		 * @return {@code true}, if ready parsing the file, {@code false}, if
		 *         reading the file should be continued.
		 */
		boolean parse(String line);
	}

	/**
	 * Parser to update statistics of added local addresses.
	 */
	private class UdpParser implements Parser {

		private static final String LOCAL_ADDRESS = "local_address";
		private static final String DROPS = "drops";

		/**
		 * Flag indicate to read the headline.
		 */
		private boolean start;
		/**
		 * Index of the local address field.
		 */
		private int localAddressIndex;
		/**
		 * Index of the drops field.
		 */
		private int dropsIndex;

		private UdpParser() {
		}

		@Override
		public void start() {
			start = true;
		}

		@Override
		public boolean parse(String line) {
			String[] fields = line.split("\\s+");
			if (start) {
				start = false;
				localAddressIndex = indexOf(fields, LOCAL_ADDRESS);
				// the data table seems to separate "tx_queue" "rx_queue"
				// and "tr" "tm->when" by ":", not by space " ". Therefore -2
				dropsIndex = indexOf(fields, DROPS) - 2;
				return localAddressIndex < 0 || dropsIndex < 0;
			}
			if (localAddressIndex < fields.length && dropsIndex < fields.length) {
				SimpleCounterStatistic statistic = getStatistic(fields[localAddressIndex]);
				if (statistic != null) {
					try {
						long current = Long.parseLong(fields[dropsIndex].trim());
						SimpleCounterStatistic externalStatistic = externalStatistics
								.get(fields[localAddressIndex].toUpperCase());
						if (externalStatistic != null) {
							externalStatistic.set(current);
						}
						return update(statistic, current);
					} catch (NumberFormatException ex) {
					}
				}
			}
			return false;
		}

		/**
		 * Get statistic of provided local address.
		 * 
		 * @param localAddress local address as string in format of
		 *            "/proc/net/udp"
		 * @return statistic, or {@code null}, if not available.
		 */
		protected SimpleCounterStatistic getStatistic(String localAddress) {
			return getByKey(localAddress.toUpperCase());
		}

		/**
		 * Update the statistic with the provided value.
		 * 
		 * @param statistic statistic to be updated
		 * @param value value to update the statistic.
		 * @return {@code true}, if ready parsing the file, {@code false}, if
		 *         reading the file should be continued.
		 */
		protected boolean update(SimpleCounterStatistic statistic, long value) {
			statistic.set(value);
			return false;
		}
	}

	/**
	 * Parser to add a new local address.
	 */
	private class UdpAddParser extends UdpParser {

		private final SimpleCounterStatistic externalStatistic;
		private final InetSocketAddress local;
		private final String localIPv4;
		private final String localIPv6;
		private String key;

		private UdpAddParser(InetSocketAddress local, SimpleCounterStatistic externalStatistic) {
			this.local = local;
			this.externalStatistic = externalStatistic;
			String localIP = getAddress(local);
			if (localIP.length() <= 13) {
				this.localIPv4 = localIP;
				this.localIPv6 = expandAddressForIpv6(localIP);
				LOGGER.trace("search {}/{}", localIP, localIPv6);
			} else {
				this.localIPv4 = null;
				this.localIPv6 = localIP;
				LOGGER.trace("search {}", localIP);
			}
		}

		@Override
		protected SimpleCounterStatistic getStatistic(String localAddress) {
			if (localAddress.equalsIgnoreCase(localIPv6)) {
				key = localIPv6;
			}
			if (localAddress.equalsIgnoreCase(localIPv4)) {
				key = localIPv4;
			}
			if (key != null) {
				return new SimpleCounterStatistic(StringUtil.toDisplayString(local), align);
			}
			return null;
		}

		@Override
		protected boolean update(SimpleCounterStatistic statistic, long value) {
			if (key != null) {
				statistic.set(value);
				statistic.reset();
				addByKey(key, statistic);
				LOGGER.trace("added {}", key);
				if (externalStatistic != null) {
					externalStatistic.set(value);
					externalStatistic.reset();
					externalStatistics.put(key, externalStatistic);
				} else {
					externalStatistics.remove(key);
				}
			}
			return true;
		}

		private boolean added() {
			return key != null;
		}
	}

	/**
	 * Index of value in fields
	 * 
	 * @param fields array with value of fields
	 * @param value value to search
	 * @return (first) index of value in fields, {@code -1}, if not found.
	 */
	private static int indexOf(String[] fields, String value) {
		for (int index = 0; index < fields.length; ++index) {
			if (value.equalsIgnoreCase(fields[index])) {
				return index;
			}
		}
		return -1;
	}

	/**
	 * Expand textual local address from "/proc/net/udp" format to
	 * "/proc/net/udp6".
	 * 
	 * @param local local address in "/proc/net/udp" format
	 * @return address in "/proc/net/udp6" format.
	 */

	private static String expandAddressForIpv6(String local) {
		if (local.length() <= 13) {
			if (local.startsWith(IPV4_ANY)) {
				return IPV4_ANY_HEADER + local;
			} else {
				return IPV4_HEADER + local;
			}
		}
		return local;
	}

	/**
	 * Get local address in "/proc/net/udp" or "/proc/net/udp6" format.
	 * 
	 * <pre>
	 * "/proc/net/udp" "0100007F:1697" for "127.0.0.1:5783"
	 * "/proc/net/udp6" "0000000000000000FFFF00000100007F:1697" for "127.0.0.1:5783"
	 * "/proc/net/udp6" "00000000000000000000000001000000:1697" for "[::1]:5783"
	 * </pre>
	 * 
	 * @param local local address
	 * @return address in "/proc/net/udp" or "/proc/net/udp6" format
	 */
	private static String getAddress(InetSocketAddress local) {
		int port = local.getPort();
		byte[] address = local.getAddress().getAddress();
		StringBuilder builder = new StringBuilder();
		if (address.length == 4) {
			append(builder, address, 0);
		} else {
			append(builder, address, 0);
			append(builder, address, 4);
			append(builder, address, 8);
			append(builder, address, 12);
		}
		builder.append(":").append(String.format("%04X", port));
		return builder.toString();
	}

	/**
	 * Append quad in hex to builder.
	 * 
	 * <pre>
	 * [127,0,0,1] to "0100007F"
	 * </pre>
	 * 
	 * @param builder builder to append hey value
	 * @param address bytes
	 * @param index starting index of quad in address
	 */
	private static void append(StringBuilder builder, byte[] address, int index) {
		int end = index + 4;
		while (end > index) {
			builder.append(String.format("%02X", 0xff & address[--end]));
		}
	}

}
