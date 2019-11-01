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
package org.eclipse.californium.scandium;

import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DtlsHealth {

	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(DTLSConnector.class.getCanonicalName() + ".health");

	public final AtomicInteger pendingHandshakes = new AtomicInteger();

	private final SimpleCounterStatistic.AlignGroup align = new SimpleCounterStatistic.AlignGroup();
	public final SimpleCounterStatistic succeededHandshakes = new SimpleCounterStatistic("handshakes succeeded", align);
	public final SimpleCounterStatistic failedHandshakes = new SimpleCounterStatistic("handshakes failed", align);
	public final SimpleCounterStatistic records = new SimpleCounterStatistic("records", align);
	public final SimpleCounterStatistic droppedRecords = new SimpleCounterStatistic("dropped records", align);

	public void dump(String tag, int maxConnections, int remainingCapacity, int pendingWithoutVerify) {
		try {
			if (records.isUsed()) {
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
				log.append(head).append(records).append(eol);
				log.append(head).append(droppedRecords);
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
