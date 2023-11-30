/*******************************************************************************
 * Copyright (c) 2020 Bosch IO GmbH and others.
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
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.NotForAndroid;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Netstat logger.
 * 
 * Dumps network statistic informations from OS. Currently only supports unix
 * and UDP.
 * 
 * @since 2.2
 */
@NotForAndroid
public class NetStatLogger extends CounterStatisticManager {

	/**
	 * The logger.
	 * 
	 * @deprecated scope will change to private.
	 */
	@Deprecated
	protected static final Logger LOGGER = LoggerFactory.getLogger(NetStatLogger.class);

	// Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors
	// InCsumErrors IgnoredMulti
	protected final SimpleCounterStatistic sent = new SimpleCounterStatistic("OutDatagrams", align);
	protected final SimpleCounterStatistic received = new SimpleCounterStatistic("InDatagrams", align);
	protected final SimpleCounterStatistic sendBufferErrors = new SimpleCounterStatistic("SndbufErrors", align);
	protected final SimpleCounterStatistic receiveBufferErrors = new SimpleCounterStatistic("RcvbufErrors", align);
	protected final SimpleCounterStatistic inErrors = new SimpleCounterStatistic("InErrors", align);
	protected final SimpleCounterStatistic inChecksumErrors = new SimpleCounterStatistic("InCsumErrors", align);
	protected final SimpleCounterStatistic noPorts = new SimpleCounterStatistic("NoPorts", align);

	/**
	 * File to read.
	 * 
	 * @since 3.1
	 */
	private final File file;
	/**
	 * Parser for lines.
	 * 
	 * @since 3.1
	 */
	private final Parser parser;

	/**
	 * Create passive netstat logger for IPv4.
	 * 
	 * {@link #dump()} is intended to be called externally.
	 * 
	 * @param tag logging tag
	 * @deprecated use {@link NetStatLogger#NetStatLogger(String, boolean)}
	 *             instead
	 */
	public NetStatLogger(String tag) {
		this(tag, false);
	}

	/**
	 * Create passive netstat logger.
	 * 
	 * {@link #dump()} is intended to be called externally.
	 * 
	 * @param tag logging tag
	 * @param ipv6 {@code true} for IPv6, {@code false} for IPv4
	 * @since 3.1
	 */
	public NetStatLogger(String tag, boolean ipv6) {
		super(tag);
		this.parser = ipv6 ? new SnmpIPv6Parser() : new SnmpIPv4Parser();
		this.file = getFile(ipv6);
		if (isEnabled()) {
			init();
		}
	}

	/**
	 * Create active netstat logger for IPv4.
	 * 
	 * {@link #dump()} is called repeated with configurable interval after
	 * {@link #start()} is called.
	 * 
	 * @param tag logging tag
	 * @param interval interval. {@code 0} to disable active logging.
	 * @param unit time unit of interval
	 * @param executor executor executor to schedule active logging.
	 * @throws NullPointerException if executor is {@code null}
	 * @since 3.0 (added unit)
	 * @deprecated use {@link NetStatLogger#NetStatLogger(String, boolean)}
	 *             instead and call {@link #dump()} externally.
	 */
	public NetStatLogger(String tag, int interval, TimeUnit unit, ScheduledExecutorService executor) {
		super(tag, interval, unit, executor);
		this.parser = new SnmpIPv4Parser();
		this.file = getFile(false);
		if (isEnabled()) {
			init();
		}
	}

	private void init() {
		add(sent);
		add(received);
		add(sendBufferErrors);
		add(receiveBufferErrors);
		add(inErrors);
		add(inChecksumErrors);
		add(noPorts);

		read();
		reset();
	}

	@Override
	public boolean isEnabled() {
		return LOGGER.isInfoEnabled() && file.canRead();
	}

	@Override
	public void dump() {
		if (isEnabled()) {
			read();
			if (LOGGER.isDebugEnabled()) {
				try {

					if (sent.isUsed() || received.isUsed() || sendBufferErrors.isUsed()
							|| receiveBufferErrors.isUsed()) {
						String eol = StringUtil.lineSeparator();
						String head = "   " + tag;
						StringBuilder log = new StringBuilder();
						log.append(tag).append("network statistic:").append(eol);
						log.append(head).append(sent).append(eol);
						log.append(head).append(received).append(eol);
						log.append(head).append(sendBufferErrors).append(eol);
						log.append(head).append(receiveBufferErrors).append(eol);
						log.append(head).append(inErrors).append(eol);
						log.append(head).append(inChecksumErrors).append(eol);
						log.append(head).append(noPorts);
						LOGGER.debug("{}", log);
					}
				} catch (Throwable e) {
					LOGGER.error("{}", tag, e);
				}
			}
			transferCounter();
		}
	}

	private void read() {

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

	/**
	 * Get file to read network statistic.
	 * 
	 * @param ipv6 {@code true} for IPv6, {@code false} for IPv4
	 * @return file to read network statistic.
	 * @since 3.1
	 */
	private static File getFile(boolean ipv6) {
		String path = "/proc/net/snmp";
		if (ipv6) {
			path += "6";
		}
		LOGGER.info("File: {}", path);
		return new File(path);
	}

	private interface Parser {

		void start();

		boolean parse(String line);
	}

	private class SnmpIPv4Parser implements Parser {

		String heads;

		@Override
		public void start() {
			heads = null;
		}

		@Override
		public boolean parse(String line) {
			if (heads == null) {
				if (line.startsWith("Udp: ")) {
					heads = line;
				}
				return false;
			} else {
				String[] headFields = heads.split("\\s+");
				String[] valueFields = line.split("\\s+");
				for (int index = 1; index < headFields.length; ++index) {
					SimpleCounterStatistic statistic = getByKey(headFields[index]);
					if (statistic != null) {
						try {
							long current = Long.parseLong(valueFields[index]);
							statistic.set(current);
						} catch (NumberFormatException ex) {
						}
					}
				}

				return true;
			}
		}

	}

	private class SnmpIPv6Parser implements Parser {

		@Override
		public void start() {
		}

		@Override
		public boolean parse(String line) {
			if (line.startsWith("Udp6")) {
				String[] fields = line.split("\\s+");
				if (fields.length == 2) {
					String name = fields[0].substring(4);
					SimpleCounterStatistic statistic = getByKey(name);
					if (statistic != null) {
						try {
							long current = Long.parseLong(fields[1].trim());
							statistic.set(current);
						} catch (NumberFormatException ex) {
						}
					}
				}
			}
			return false;
		}

	}
}
