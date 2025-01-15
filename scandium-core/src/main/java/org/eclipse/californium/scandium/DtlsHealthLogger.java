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

	/**
	 * Message dropping is accessed via {@link #getByKey(String)}.
	 * 
	 * @since 3.1
	 */
	public static final String DROPPED_UDP_MESSAGES = "dropped udp messages";

	private final AtomicInteger pendingHandshakes = new AtomicInteger();

	protected final SimpleCounterStatistic.AlignGroup align = new SimpleCounterStatistic.AlignGroup();
	private final SimpleCounterStatistic connections = new SimpleCounterStatistic("connections", align);
	private final SimpleCounterStatistic succeededHandshakes = new SimpleCounterStatistic("handshakes succeeded",
			align);
	private final SimpleCounterStatistic failedHandshakes = new SimpleCounterStatistic("handshakes failed", align);
	private final SimpleCounterStatistic receivedRecords = new SimpleCounterStatistic("received records", align);
	private final SimpleCounterStatistic droppedReceivedRecords = new SimpleCounterStatistic("dropped received records",
			align);
	private final SimpleCounterStatistic droppedReceivedMacErrors = new SimpleCounterStatistic(
			"dropped received mac-errors", align);
	private final SimpleCounterStatistic sentRecords = new SimpleCounterStatistic("sending records", align);
	private final SimpleCounterStatistic droppedSentRecords = new SimpleCounterStatistic("dropped sending records",
			align);
	private final SimpleCounterStatistic droppedMessages = new SimpleCounterStatistic(DROPPED_UDP_MESSAGES, align);
	private final SimpleCounterStatistic pendingIncoming = new SimpleCounterStatistic("pending in jobs", align);
	private final SimpleCounterStatistic pendingOutgoing = new SimpleCounterStatistic("pending out jobs", align);
	private final SimpleCounterStatistic pendingHandshakeJobs = new SimpleCounterStatistic("pending handshake jobs",
			align);
	private final SimpleCounterStatistic missingAuthorizations = new SimpleCounterStatistic(
			"application missing authorizations", align);
	private final SimpleCounterStatistic rejectedAuthorizations = new SimpleCounterStatistic(
			"application rejected authorizations", align);

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

	private void init() {
		add(connections);
		add(succeededHandshakes);
		add(failedHandshakes);
		add(receivedRecords);
		add(droppedReceivedRecords);
		add(droppedReceivedMacErrors);
		add(sentRecords);
		add(droppedSentRecords);
		add(droppedMessages);
		add(pendingIncoming);
		add(pendingOutgoing);
		add(pendingHandshakeJobs);
		add(missingAuthorizations);
		add(rejectedAuthorizations);
	}

	@Override
	public void dump() {
		try {
			if (isEnabled()) {
				if (isUsed() && LOGGER.isDebugEnabled()) {
					String eol = StringUtil.lineSeparator();
					String head = "   " + tag;
					StringBuilder log = new StringBuilder();
					log.append(tag).append("dtls statistic:").append(eol);
					log.append(head).append(connections).append(eol);
					log.append(head).append(succeededHandshakes).append(eol);
					log.append(head).append(failedHandshakes).append(eol);
					log.append(head).append(sentRecords).append(eol);
					log.append(head).append(droppedSentRecords).append(eol);
					log.append(head).append(receivedRecords).append(eol);
					log.append(head).append(droppedReceivedRecords).append(eol);
					log.append(head).append(droppedReceivedMacErrors);
					if (droppedMessages.isStarted()) {
						log.append(eol).append(head).append(droppedMessages);
					}
					log.append(eol).append(head).append(pendingIncoming);
					log.append(eol).append(head).append(pendingOutgoing);
					log.append(eol).append(head).append(pendingHandshakeJobs);
					if (rejectedAuthorizations.isStarted() || missingAuthorizations.isStarted()) {
						log.append(eol).append(head).append(missingAuthorizations);
						log.append(eol).append(head).append(rejectedAuthorizations);
					}
					dump(head, log);
					LOGGER.debug("{}", log);
				}
				transferCounter();
			}
		} catch (Throwable e) {
			LOGGER.error("{}", tag, e);
		}
	}

	@Override
	public void dump(String tag, int maxConnections, int remainingCapacity) {
		try {
			if (isEnabled()) {
				connections.transferCounter();
				connections.set(maxConnections - remainingCapacity);
				if (isUsed() && LOGGER.isDebugEnabled()) {
					String eol = StringUtil.lineSeparator();
					String head = "   " + tag;
					String associations = "associations";
					String handshakes = "handshakes pending";
					align.add(associations);
					align.add(handshakes);
					StringBuilder log = new StringBuilder();
					log.append(tag).append("dtls statistic:").append(eol);
					String msg = SimpleCounterStatistic.format(align.getAlign(), associations,
							maxConnections - remainingCapacity);
					log.append(head).append(msg);
					log.append(" (").append(remainingCapacity).append(" remaining capacity).").append(eol);
					msg = SimpleCounterStatistic.format(align.getAlign(), handshakes, pendingHandshakes.get());
					log.append(head).append(msg);
					log.append(head).append(succeededHandshakes).append(eol);
					log.append(head).append(failedHandshakes).append(eol);
					log.append(head).append(sentRecords).append(eol);
					log.append(head).append(droppedSentRecords).append(eol);
					log.append(head).append(receivedRecords).append(eol);
					log.append(head).append(droppedReceivedRecords).append(eol);
					log.append(head).append(droppedReceivedMacErrors);
					if (droppedMessages.isStarted()) {
						log.append(eol).append(head).append(droppedMessages);
					}
					log.append(eol).append(head).append(pendingIncoming);
					log.append(eol).append(head).append(pendingOutgoing);
					log.append(eol).append(head).append(pendingHandshakeJobs);
					if (rejectedAuthorizations.isStarted() || missingAuthorizations.isStarted()) {
						log.append(eol).append(head).append(missingAuthorizations);
						log.append(eol).append(head).append(rejectedAuthorizations);
					}
					dump(head, log);
					LOGGER.debug("{}", log);
				}
				transferCounter();
			}
		} catch (Throwable e) {
			LOGGER.error("{}", tag, e);
		}
	}

	/**
	 * Check, if health logger is used.
	 * 
	 * @return {@code true}, if used and dump must be written, {@code false},
	 *         otherwise.
	 * @since 2.5
	 */
	protected boolean isUsed() {
		return receivedRecords.isUsed() || sentRecords.isUsed();
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
		return LOGGER.isInfoEnabled();
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

	@Override
	public void receivingMacError() {
		droppedReceivedMacErrors.increment();
	}

	@Override
	public void setConnections(int count) {
		connections.set(count);
	}

	@Override
	public void setPendingIncomingJobs(int count) {
		pendingIncoming.set(count);
	}

	@Override
	public void setPendingOutgoingJobs(int count) {
		pendingOutgoing.set(count);
	}

	@Override
	public void setPendingHandshakeJobs(int count) {
		pendingHandshakeJobs.set(count);
	}

	@Override
	public void applicationAuthorizationRejected(boolean rejected) {
		if (rejected) {
			rejectedAuthorizations.increment();
		} else {
			missingAuthorizations.increment();
		}
	}

}
