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

	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(NetStatLogger.class);

	/**
	 * File to read the OS network statistic.
	 */
	private static final File SNMP = new File("/proc/net/snmp");
	// Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors
	// InCsumErrors IgnoredMulti
	private final SimpleCounterStatistic sent = new SimpleCounterStatistic("OutDatagrams", align);
	private final SimpleCounterStatistic received = new SimpleCounterStatistic("InDatagrams", align);
	private final SimpleCounterStatistic sendBufferErrors = new SimpleCounterStatistic("SndbufErrors", align);
	private final SimpleCounterStatistic receiveBufferErrors = new SimpleCounterStatistic("RcvbufErrors", align);
	private final SimpleCounterStatistic inErrors = new SimpleCounterStatistic("InErrors", align);
	private final SimpleCounterStatistic inChecksumErrors = new SimpleCounterStatistic("InCsumErrors", align);
	private final SimpleCounterStatistic noPorts = new SimpleCounterStatistic("NoPorts", align);

	/**
	 * Start values to adjust logged values.
	 */
	private final long[] START = new long[10];

	/**
	 * Create passive netstat logger.
	 * 
	 * {@link #dump()} is intended to be called externally.
	 * 
	 * @param tag logging tag
	 */
	public NetStatLogger(String tag) {
		super(tag);
		if (isEnabled()) {
			init();
		}
	}

	/**
	 * Create active netstat logger.
	 * 
	 * {@link #dump()} is called repeated with configurable interval.
	 * 
	 * @param tag logging tag
	 * @param interval interval in seconds. {@code 0} to disable active logging.
	 * @param executor executor executor to schedule active logging.
	 * @throws NullPointerException if executor is {@code null}
	 */
	public NetStatLogger(String tag, int interval, ScheduledExecutorService executor) {
		super(tag, interval, executor);
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
		read(true);
	}

	@Override
	public boolean isEnabled() {
		return LOGGER.isDebugEnabled() && SNMP.canRead();
	}

	@Override
	public void dump() {
		if (isEnabled()) {
			try {
				read(false);
				if (sent.isUsed() || received.isUsed()) {
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
	}

	private void read(boolean start) {

		try (BufferedReader reader = new BufferedReader(new FileReader(SNMP))) {
			String head = null;
			String values = null;
			String line;
			while ((line = reader.readLine()) != null) {
				if (line.startsWith("Udp: ")) {
					head = line;
					values = reader.readLine();
					break;
				}
			}
			if (head != null) {
				String[] headFields = head.split(" ");
				String[] valueFields = values.split(" ");
				for (int index = 1; index < headFields.length; ++index) {
					SimpleCounterStatistic statistic = get(headFields[index]);
					if (statistic != null) {
						try {
							long current = Long.parseLong(valueFields[index]);
							if (start) {
								START[index] = current;
							} else {
								current -= START[index];
								long previous = statistic.getCounter();
								statistic.increment((int) (current - previous));
							}
						} catch (NumberFormatException ex) {
						}
					}
				}
			}
		} catch (FileNotFoundException e) {
			LOGGER.warn("{} missing!", SNMP.getAbsolutePath(), e);
		} catch (IOException e) {
			LOGGER.warn("{} error!", SNMP.getAbsolutePath(), e);
		}
	}
}
