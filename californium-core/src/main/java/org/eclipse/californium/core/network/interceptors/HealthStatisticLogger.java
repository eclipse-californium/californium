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
package org.eclipse.californium.core.network.interceptors;

import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Health implementation using counter and logging for result.
 * @since 2.1
 */
public class HealthStatisticLogger extends CounterStatisticManager implements MessageInterceptor {

	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(HealthStatisticLogger.class);

	private final SimpleCounterStatistic sentRequests = new SimpleCounterStatistic("requests", align);
	private final SimpleCounterStatistic sentResponses = new SimpleCounterStatistic("responses", align);
	private final SimpleCounterStatistic sentRejects = new SimpleCounterStatistic("rejects", align);
	private final SimpleCounterStatistic sentAcknowledges = new SimpleCounterStatistic("acks", align);
	private final SimpleCounterStatistic resentRequests = new SimpleCounterStatistic("request retransmissions", align);
	private final SimpleCounterStatistic resentResponses = new SimpleCounterStatistic("response retransmissions",
			align);
	private final SimpleCounterStatistic sendErrors = new SimpleCounterStatistic("errors", align);

	private final SimpleCounterStatistic receivedRequests = new SimpleCounterStatistic("requests", align);
	private final SimpleCounterStatistic receivedResponses = new SimpleCounterStatistic("responses", align);
	private final SimpleCounterStatistic receivedRejects = new SimpleCounterStatistic("rejects", align);
	private final SimpleCounterStatistic receivedAcknowledges = new SimpleCounterStatistic("acks", align);
	private final SimpleCounterStatistic duplicateRequests = new SimpleCounterStatistic("duplicate requests", align);
	private final SimpleCounterStatistic duplicateResponses = new SimpleCounterStatistic("duplicate responses", align);
	private final SimpleCounterStatistic ignoredMessages = new SimpleCounterStatistic("ignored", align);
	private final SimpleCounterStatistic offloadedMessages = new SimpleCounterStatistic("offloaded", align);

	/**
	 * {@code true} dump statistic for udp, {@code false}, dump statistic for
	 * tcp.
	 */
	private final boolean udp;

	/**
	 * Create passive health logger.
	 * 
	 * {@link #dump()} is intended to be called externally.
	 * 
	 * @param tag logging tag
	 * @param udp {@code true} dump statistic for udp, {@code false}, dump
	 *            statistic for tcp.
	 */
	public HealthStatisticLogger(String tag, boolean udp) {
		super(tag);
		this.udp = udp;
		init();
	}

	/**
	 * Create active health logger.
	 * 
	 * {@link #dump()} is called repeated with configurable interval.
	 * 
	 * @param tag logging tag
	 * @param udp {@code true} dump statistic for udp, {@code false}, dump
	 *            statistic for tcp.
	 * @param interval interval in seconds. {@code 0} to disable active logging.
	 * @param executor executor executor to schedule active logging.
	 * @throws NullPointerException if executor is {@code null}
	 */
	public HealthStatisticLogger(String tag, boolean udp, int interval, ScheduledExecutorService executor) {
		super(tag, interval, executor);
		this.udp = udp;
		init();
	}

	private void init() {
		add("send-", sentRequests);
		add("send-", sentResponses);
		add("send-", sentAcknowledges);
		add("send-", sentRejects);
		add("send-", resentRequests);
		add("send-", resentResponses);
		add("send-", sendErrors);

		add("recv-", receivedRequests);
		add("recv-", receivedResponses);
		add("recv-", receivedAcknowledges);
		add("recv-", receivedRejects);
		add("recv-", duplicateRequests);
		add("recv-", duplicateResponses);
		add("recv-", ignoredMessages);
	}

	@Override
	public boolean isEnabled() {
		return LOGGER.isDebugEnabled();
	}

	@Override
	public void dump() {
		try {
			if (receivedRequests.isUsed() || sentRequests.isUsed() || sendErrors.isUsed()) {
				String eol = StringUtil.lineSeparator();
				String head = "   " + tag;
				StringBuilder log = new StringBuilder();
				log.append(tag).append("endpoint statistic:").append(eol);
				log.append(tag).append("send statistic:").append(eol);
				log.append(head).append(sentRequests).append(eol);
				log.append(head).append(sentResponses).append(eol);
				if (udp) {
					log.append(head).append(sentAcknowledges).append(eol);
					log.append(head).append(sentRejects).append(eol);
					log.append(head).append(resentRequests).append(eol);
					log.append(head).append(resentResponses).append(eol);
				}
				log.append(head).append(sendErrors).append(eol);
				log.append(tag).append("receive statistic:").append(eol);
				log.append(head).append(receivedRequests).append(eol);
				log.append(head).append(receivedResponses).append(eol);
				if (udp) {
					log.append(head).append(receivedAcknowledges).append(eol);
					log.append(head).append(receivedRejects).append(eol);
					log.append(head).append(duplicateRequests).append(eol);
					log.append(head).append(duplicateResponses).append(eol);
					log.append(head).append(offloadedMessages).append(eol);
				}
				log.append(head).append(ignoredMessages).append(eol);
				long sent = getSentCounters();
				long processed = getProcessedCounters();
				log.append(tag).append("sent ").append(sent).append(", received ").append(processed);
				LOGGER.debug("{}", log);
			}
		} catch (Throwable e) {
			LOGGER.error("{}", tag, e);
		}
	}

	public long getSentCounters() {
		long sent = sentRequests.getCounter() + sentResponses.getCounter() + sentAcknowledges.getCounter()
				+ sentRejects.getCounter() + resentRequests.getCounter() + resentResponses.getCounter();
		return sent;
	}

	public long getProcessedCounters() {
		long processed = receivedRequests.getCounter() + receivedResponses.getCounter()
				+ receivedAcknowledges.getCounter() + receivedRejects.getCounter() + duplicateRequests.getCounter()
				+ duplicateResponses.getCounter() + ignoredMessages.getCounter();
		return processed;
	}

	@Override
	public void sendRequest(Request request) {
		if (request.getSendError() != null) {
			sendErrors.increment();
		} else if (request.isDuplicate()) {
			resentRequests.increment();
		} else {
			sentRequests.increment();
		}
	}

	@Override
	public void sendResponse(Response response) {
		if (response.getOffloadMode() != null) {
			offloadedMessages.increment();
		}
		if (response.getSendError() != null) {
			sendErrors.increment();
		} else if (response.isDuplicate()) {
			resentResponses.increment();
		} else {
			sentResponses.increment();
		}
	}

	@Override
	public void sendEmptyMessage(EmptyMessage message) {
		if (message.getSendError() != null) {
			sendErrors.increment();
		} else if (message.getType() == CoAP.Type.ACK) {
			sentAcknowledges.increment();
		} else {
			sentRejects.increment();
		}
	}

	@Override
	public void receiveRequest(Request request) {
		if (request.isDuplicate()) {
			duplicateRequests.increment();
		} else {
			receivedRequests.increment();
		}
	}

	@Override
	public void receiveResponse(Response response) {
		if (response.isCanceled()) {
			ignoredMessages.increment();
		} else if (response.isDuplicate()) {
			duplicateResponses.increment();
		} else {
			receivedResponses.increment();
		}
	}

	@Override
	public void receiveEmptyMessage(EmptyMessage message) {
		if (message.isCanceled()) {
			ignoredMessages.increment();
		} else if (message.getType() == CoAP.Type.ACK) {
			receivedAcknowledges.increment();
		} else {
			receivedRejects.increment();
		}
	}
}
