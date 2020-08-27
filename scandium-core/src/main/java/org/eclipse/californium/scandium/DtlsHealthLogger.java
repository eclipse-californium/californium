/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.scandium;

import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.NoPublicAPI;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Health implementation using counter and logging for results.
 */
@NoPublicAPI
public class DtlsHealthLogger extends CounterStatisticManager implements DtlsHealth {

	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnector.class.getCanonicalName() + ".health");

	private final AtomicInteger pendingHandshakes = new AtomicInteger();

	protected final SimpleCounterStatistic.AlignGroup align = new SimpleCounterStatistic.AlignGroup();
	private final SimpleCounterStatistic succeededHandshakes = new SimpleCounterStatistic("handshakes succeeded",
			align);
	private final SimpleCounterStatistic failedHandshakes = new SimpleCounterStatistic("handshakes failed", align);
	private final SimpleCounterStatistic receivedRecords = new SimpleCounterStatistic("received records", align);
	private final SimpleCounterStatistic droppedReceivedRecords = new SimpleCounterStatistic("dropped received records",
			align);
	private final SimpleCounterStatistic sentRecords = new SimpleCounterStatistic("sending records", align);
	private final SimpleCounterStatistic droppedSentRecords = new SimpleCounterStatistic("dropped sending records",
			align);

	/**
	 * Create passive dtls health logger.
	 */
	public DtlsHealthLogger() {
		this("");
	}

	/**
	 * Create passive dtls health logger with logging tag.
	 * 
	 * @param tag logging tag
	 */
	public DtlsHealthLogger(String tag) {
		super(tag);
		init();
	}

	/**
	 * Create active dtls health logger with logging tag.
	 * 
	 * @param tag logging tag
	 * @param udp not used
	 * @param interval interval in seconds. {@code 0} to disable actively calling
	 *            {@link #dump()}.
	 * @param executor executor to schedule active calls of {@link #dump()}.
	 * @deprecated use
	 *             {@link #DtlsHealthLogger(String, int, ScheduledExecutorService)}
	 *             instead.
	 */
	@Deprecated
	public DtlsHealthLogger(String tag, boolean udp, int interval, ScheduledExecutorService executor) {
		this(tag, interval, executor);
	}

	/**
	 * Create active dtls health logger with logging tag.
	 * 
	 * @param tag logging tag
	 * @param interval interval in seconds. {@code 0} to disable actively
	 *            calling {@link #dump()}.
	 * @param executor executor to schedule active calls of {@link #dump()}.
	 * @since 2.5
	 */
	public DtlsHealthLogger(String tag, int interval, ScheduledExecutorService executor) {
		super(tag, interval, executor);
		init();
	}

	private void init() {
		add(succeededHandshakes);
		add(failedHandshakes);
		add(receivedRecords);
		add(droppedReceivedRecords);
		add(sentRecords);
		add(droppedSentRecords);
	}

	@Override
	public void dump() {
		try {
			if (receivedRecords.isUsed() || sentRecords.isUsed()) {
				String eol = StringUtil.lineSeparator();
				String head = "   " + tag;
				StringBuilder log = new StringBuilder();
				log.append(tag).append("statistic:").append(eol);
				log.append(head).append(succeededHandshakes).append(eol);
				log.append(head).append(failedHandshakes).append(eol);
				log.append(head).append(sentRecords).append(eol);
				log.append(head).append(droppedSentRecords).append(eol);
				log.append(head).append(receivedRecords).append(eol);
				log.append(head).append(droppedReceivedRecords);
				dump(head, log);
				LOGGER.debug("{}", log);
			}
		} catch (Throwable e) {
			LOGGER.error("{}", tag, e);
		}
	}

	public void dump(String tag, int maxConnections, int remainingCapacity, int pendingWithoutVerify) {
		try {
			if (receivedRecords.isUsed() || sentRecords.isUsed()) {
				String eol = StringUtil.lineSeparator();
				String head = "   " + tag;
				String associations = "associations";
				String handshakes = "handshakes pending";
				align.add(associations);
				align.add(handshakes);
				StringBuilder log = new StringBuilder();
				log.append(tag).append("statistic:").append(eol);
				String msg = SimpleCounterStatistic.format(align.getAlign(), associations,
						maxConnections - remainingCapacity);
				log.append(head).append(msg);
				log.append(" (").append(remainingCapacity).append(" remaining capacity).").append(eol);
				msg = SimpleCounterStatistic.format(align.getAlign(), handshakes, pendingHandshakes.get());
				log.append(head).append(msg);
				log.append(" (").append(pendingWithoutVerify).append(" without verify).").append(eol);
				log.append(head).append(succeededHandshakes).append(eol);
				log.append(head).append(failedHandshakes).append(eol);
				log.append(head).append(sentRecords).append(eol);
				log.append(head).append(droppedSentRecords).append(eol);
				log.append(head).append(receivedRecords).append(eol);
				log.append(head).append(droppedReceivedRecords);
				dump(head, log);
				LOGGER.debug("{}", log);
			}
		} catch (Throwable e) {
			LOGGER.error("{}", tag, e);
		}
	}

	/**
	 * Dump additional health data.
	 * 
	 * Intended to be overridden by derived class.
	 * 
	 * @param head head for logging lines
	 * @param log logging lines
	 * @since 2.5
	 */
	protected void dump(String head, StringBuilder log) {
		// empty default implementation
	}

	@Override
	public boolean isEnabled() {
		return LOGGER.isDebugEnabled();
	}

	@Override
	public void startHandshake() {
		pendingHandshakes.incrementAndGet();
	}

	@Override
	public void endHandshake(boolean success) {
		pendingHandshakes.decrementAndGet();
		if (success) {
			succeededHandshakes.increment();
		} else {
			failedHandshakes.increment();
		}
	}

	@Override
	public void receivingRecord(boolean drop) {
		if (drop) {
			droppedReceivedRecords.increment();
		} else {
			receivedRecords.increment();
		}
	}

	@Override
	public void sendingRecord(boolean drop) {
		if (drop) {
			droppedSentRecords.increment();
		} else {
			sentRecords.increment();
		}
	}
}
