/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
package org.eclipse.californium.core.observe;

import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Observe health implementation using counter and logging for result.
 * 
 * @since 3.6
 */
public class ObserveStatisticLogger extends CounterStatisticManager implements ObserveHealth {

	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(ObserveStatisticLogger.class);

	private final SimpleCounterStatistic observes = new SimpleCounterStatistic("observes", align);
	private final SimpleCounterStatistic endpoints = new SimpleCounterStatistic("observing-endpoints", align);
	private final SimpleCounterStatistic observeRequests = new SimpleCounterStatistic("observe-request", align);
	private final SimpleCounterStatistic cancelRequests = new SimpleCounterStatistic("cancel-request", align);
	private final SimpleCounterStatistic rejectedNotifies = new SimpleCounterStatistic("rejected-notifies", align);

	/**
	 * Create health logger.
	 * 
	 * @param tag logging tag
	 */
	public ObserveStatisticLogger(String tag) {
		super(tag);
		init();
	}

	private void init() {
		add(observes);
		add(endpoints);
		add(observeRequests);
		add(cancelRequests);
		add(rejectedNotifies);
	}

	@Override
	public boolean isEnabled() {
		return LOGGER.isInfoEnabled();
	}

	@Override
	public void dump() {
		try {
			if (isEnabled()) {
				if (LOGGER.isDebugEnabled()) {
					if (observeRequests.isUsed()) {
						StringBuilder log = new StringBuilder();
						String eol = StringUtil.lineSeparator();
						String head = "   " + tag;
						log.append(tag).append("observe-statistic:").append(eol);
						log.append(head).append(observes).append(eol);
						log.append(head).append(endpoints).append(eol);
						log.append(head).append(observeRequests).append(eol);
						log.append(head).append(cancelRequests).append(eol);
						log.append(head).append(rejectedNotifies);
						LOGGER.debug("{}", log);
					}
				}
				transferCounter();
			}
		} catch (Throwable e) {
			LOGGER.error("{}", tag, e);
		}
	}

	@Override
	public void setObserveRelations(int observeRelations) {
		observes.set(observeRelations);
	}

	@Override
	public void setObserveEndpoints(int observeEndpoints) {
		endpoints.set(observeEndpoints);
	}

	@Override
	public void receivingObserveRequest() {
		observeRequests.increment();
	}

	@Override
	public void receivingCancelRequest() {
		cancelRequests.increment();
	}

	@Override
	public void receivingReject() {
		rejectedNotifies.increment();
	}
}
