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
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Health implementation using counter and logging for result.
 */
public class HealthStatisticLogger implements MessagePostInterceptor {

	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(HealthStatisticLogger.class);

	private final SimpleCounterStatistic.AlignGroup align = new SimpleCounterStatistic.AlignGroup();
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

	/**
	 * Tag for logging to describe the information.
	 */
	private final String tag;
	/**
	 * Executor for active repeated health logging. {@code null}, if
	 * {@link #dump()} is called externally.
	 */
	private final ScheduledExecutorService executor;
	/**
	 * Health logging interval in seconds. {@code 0} to disable active health
	 * logging.
	 */
	private final int healthStatusInterval;
	/**
	 * Handle of scheduled task.
	 */
	private ScheduledFuture<?> taskHandle;

	/**
	 * Create passive health logger. {@link #dump()} is intended to be called
	 * externally.
	 * 
	 * @param tag logging tag
	 */
	public HealthStatisticLogger(String tag) {
		this.healthStatusInterval = 0;
		this.executor = null;
		if (LOGGER.isDebugEnabled()) {
			this.tag = StringUtil.normalizeLoggingTag(tag);
		} else {
			this.tag = null;
		}
	}

	/**
	 * /** Create active health logger.
	 * 
	 * {@link #dump()} is called repeatingly wiht configurable interval.
	 * 
	 * @param tag logging tag
	 * @param interval interval in seconds. {@code 0} to disable active logging.
	 * @param executor executor executor to schedule active logging.
	 * @throws NullPointerException if executor is {@code null}
	 */
	public HealthStatisticLogger(String tag, int interval, ScheduledExecutorService executor) {
		if (executor == null) {
			throw new NullPointerException("executor must not be null!");
		}
		if (LOGGER.isDebugEnabled()) {
			this.healthStatusInterval = interval;
			this.executor = interval > 0 ? executor : null;
			this.tag = StringUtil.normalizeLoggingTag(tag);
		} else {
			this.healthStatusInterval = 0;
			this.executor = null;
			this.tag = null;
		}
	}

	/**
	 * Check, if health logger is enabled.
	 * 
	 * @return {@code true}, if logger is enabled, {@code false}, otherwise.
	 */
	public boolean isEnabled() {
		return LOGGER.isDebugEnabled();
	}

	/**
	 * Start active health loggging.
	 */
	public synchronized void start() {
		if (executor != null && taskHandle == null) {
			taskHandle = executor.scheduleAtFixedRate(new Runnable() {

				@Override
				public void run() {
					dump();
				}

			}, healthStatusInterval, healthStatusInterval, TimeUnit.SECONDS);
		}
	}

	/**
	 * Stop active health loggging.
	 */
	public synchronized void stop() {
		if (taskHandle != null) {
			taskHandle.cancel(false);
			taskHandle = null;
		}
	}

	/**
	 * Dump health statsitic. Either called active, for
	 * {@link #InterceptorHealthLogger(String, int, ScheduledExecutorService)},
	 * or externally.
	 */
	public void dump() {
		try {
			if (receivedRequests.isUsed() || sentRequests.isUsed()) {
				String eol = StringUtil.lineSeparator();
				String head = "   " + tag;
				StringBuilder log = new StringBuilder();
				log.append(tag).append("endpoint statistic:").append(eol);
				log.append(tag).append("send statistic:").append(eol);
				log.append(head).append(sentRequests).append(eol);
				log.append(head).append(sentResponses).append(eol);
				log.append(head).append(sentAcknowledges).append(eol);
				log.append(head).append(sentRejects).append(eol);
				log.append(head).append(resentRequests).append(eol);
				log.append(head).append(resentResponses).append(eol);
				log.append(head).append(sendErrors).append(eol);
				log.append(tag).append("receive statistic:").append(eol);
				log.append(head).append(receivedRequests).append(eol);
				log.append(head).append(receivedResponses).append(eol);
				log.append(head).append(receivedAcknowledges).append(eol);
				log.append(head).append(receivedRejects).append(eol);
				log.append(head).append(duplicateRequests).append(eol);
				log.append(head).append(duplicateResponses);
				LOGGER.debug("{}", log);
			}
		} catch (Throwable e) {
			LOGGER.error("{}", tag, e);
		}
	}

	@Override
	public void sendRequest(Request request) {
		if (request.isSent()) {
			resentRequests.increment();
		} else {
			sentRequests.increment();
		}
	}

	@Override
	public void sendResponse(Response response) {
		if (response.isSent()) {
			resentResponses.increment();
		} else {
			sentResponses.increment();
		}
	}

	@Override
	public void sendEmptyMessage(EmptyMessage message) {
		if (message.getType() == CoAP.Type.ACK) {
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
		if (response.isDuplicate()) {
			duplicateResponses.increment();
		} else {
			receivedResponses.increment();
		}
	}

	@Override
	public void receiveEmptyMessage(EmptyMessage message) {
		if (message.getType() == CoAP.Type.ACK) {
			receivedAcknowledges.increment();
		} else {
			receivedRejects.increment();
		}
	}

	@Override
	public void sendError(Message message, Throwable error) {
		sendErrors.increment();
	}
}
