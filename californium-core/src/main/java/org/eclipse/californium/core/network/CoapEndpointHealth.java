/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CoapEndpointHealth {

	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(CoapEndpoint.class.getCanonicalName() + ".health");

	private final SimpleCounterStatistic.AlignGroup align = new SimpleCounterStatistic.AlignGroup();
	public final SimpleCounterStatistic sentRequests = new SimpleCounterStatistic("requests", align);
	public final SimpleCounterStatistic sentResponses = new SimpleCounterStatistic("responses", align);
	public final SimpleCounterStatistic receivedRequests = new SimpleCounterStatistic("requests", align);
	public final SimpleCounterStatistic receivedResponses = new SimpleCounterStatistic("responses", align);
	public final SimpleCounterStatistic duplicateRequests = new SimpleCounterStatistic("duplicate requests", align);
	public final SimpleCounterStatistic duplicateResponses = new SimpleCounterStatistic("duplicate responses", align);

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
				log.append(tag).append("receive statistic:").append(eol);
				log.append(head).append(receivedRequests).append(eol);
				log.append(head).append(receivedResponses).append(eol);
				log.append(head).append(duplicateRequests).append(eol);
				log.append(head).append(duplicateResponses);
				LOGGER.debug("{}", log);
			}
		} catch (Throwable e) {
			LOGGER.error("{}", tag, e);
		}
	}

	public static boolean isEnabled() {
		return LOGGER.isDebugEnabled();
	}
}
