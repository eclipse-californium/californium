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
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Health implementation using counter and logging for result.
 * 
 * @deprecated use {@link HealthStatisticLogger}
 */
@Deprecated
public class CoapEndpointHealthLogger implements CoapEndpointHealth {

	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(CoapEndpoint.class.getCanonicalName() + ".health");

	private final SimpleCounterStatistic.AlignGroup align = new SimpleCounterStatistic.AlignGroup();
	private final SimpleCounterStatistic sentRequests = new SimpleCounterStatistic("requests", align);
	private final SimpleCounterStatistic sentResponses = new SimpleCounterStatistic("responses", align);
	private final SimpleCounterStatistic sentRejects = new SimpleCounterStatistic("rejects", align);
	private final SimpleCounterStatistic resentRequests = new SimpleCounterStatistic("request retransmissions", align);
	private final SimpleCounterStatistic resentResponses = new SimpleCounterStatistic("response retransmissions",
			align);
	private final SimpleCounterStatistic sendErrors = new SimpleCounterStatistic("errors", align);
	private final SimpleCounterStatistic receivedRequests = new SimpleCounterStatistic("requests", align);
	private final SimpleCounterStatistic receivedResponses = new SimpleCounterStatistic("responses", align);
	private final SimpleCounterStatistic receivedRejects = new SimpleCounterStatistic("rejects", align);
	private final SimpleCounterStatistic duplicateRequests = new SimpleCounterStatistic("duplicate requests", align);
	private final SimpleCounterStatistic duplicateResponses = new SimpleCounterStatistic("duplicate responses", align);

	@Override
	public void dump(String tag) {
		try {
			if (receivedRequests.isUsed() || receivedResponses.isUsed()) {
				tag = StringUtil.normalizeLoggingTag(tag);
				String eol = StringUtil.lineSeparator();
				String head = "   " + tag;
				StringBuilder log = new StringBuilder();
				log.append(tag).append("endpoint statistic:").append(eol);
				log.append(tag).append("send statistic:").append(eol);
				log.append(head).append(sentRequests).append(eol);
				log.append(head).append(sentResponses).append(eol);
				log.append(head).append(sentRejects).append(eol);
				log.append(head).append(resentRequests).append(eol);
				log.append(head).append(resentResponses).append(eol);
				log.append(head).append(sendErrors).append(eol);
				log.append(tag).append("receive statistic:").append(eol);
				log.append(head).append(receivedRequests).append(eol);
				log.append(head).append(receivedResponses).append(eol);
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
	public boolean isEnabled() {
		return LOGGER.isDebugEnabled();
	}

	@Override
	public void receivedRequest(boolean duplicate) {
		if (duplicate) {
			duplicateRequests.increment();
		} else {
			receivedRequests.increment();
		}
	}

	@Override
	public void receivedResponse(boolean duplicate) {
		if (duplicate) {
			duplicateResponses.increment();
		} else {
			receivedResponses.increment();
		}
	}

	@Override
	public void receivedReject() {
		receivedRejects.increment();
	}

	@Override
	public void sentRequest(boolean retransmission) {
		if (retransmission) {
			resentRequests.increment();
		} else {
			sentRequests.increment();
		}
	}

	@Override
	public void sentResponse(boolean retransmission) {
		if (retransmission) {
			resentResponses.increment();
		} else {
			sentResponses.increment();
		}
	}

	@Override
	public void sentReject() {
		sentRejects.increment();
	}

	@Override
	public void sendError() {
		sendErrors.increment();
	}
}
