/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.s3.proxy;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.eclipse.californium.cloud.s3.http.Aws4Authorizer.WebAppAuthorization;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * S3 processor health manager.
 * 
 * @since 3.13
 */
public class S3ProcessorHealthLogger extends CounterStatisticManager implements S3ProcessorHealth {

	/** The logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(S3ProcessorHealthLogger.class);

	private static final String PROCESSING = "processing-devices";
	private static final String SUCCESS = "processed-days";
	private static final String FAILURE = "process-failures";

	private volatile boolean used = true;

	/**
	 * Creates a S3 processor health logger.
	 * 
	 * @param tag tag for associated counter statistic
	 * @param domains set of domain names
	 */
	public S3ProcessorHealthLogger(String tag, Set<String> domains) {
		super(tag);
		LOGGER.info("S3-processor: {} domains.", domains.size());
		for (String domain : domains) {
			String head = domain + "-";
			add(head, new SimpleCounterStatistic(PROCESSING));
			add(head, new SimpleCounterStatistic(SUCCESS));
			add(head, new SimpleCounterStatistic(FAILURE));
		}
	}

	@Override
	public void processedDay(String domain, int days) {
		String name = (days >= 0 ? SUCCESS : FAILURE);
		if (days < 0) {
			days = 1;
		}
		SimpleCounterStatistic statistic = getByKey(domain + "-" + name);
		if (statistic != null) {
			used = true;
			if (days > 0) {
				statistic.increment(days);
			}
		}
	}

	@Override
	public void processingDevices(String domain, int devices) {
		SimpleCounterStatistic statistic = getByKey(domain + "-" + PROCESSING);
		if (statistic != null) {
			used = true;
			if (devices < 0) {
				statistic.increment(devices);
			} else {
				statistic.set(devices);
			}
		}
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
					if (used) {
						StringBuilder log = new StringBuilder();
						String eol = StringUtil.lineSeparator();
						String head = "   " + tag;
						log.append(tag).append("s3-processor-statistic:");
						for (String key : getKeys()) {
							log.append(eol).append(head).append(getByKey(key));
						}
						LOGGER.debug("{}", log);
					}
				}
			}
		} catch (Throwable e) {
			LOGGER.error("{}", tag, e);
		}
	}

	@Override
	public List<String> getKeys(Principal principal) {
		List<String> list = new ArrayList<>();
		if (principal instanceof WebAppAuthorization) {
			WebAppAuthorization authorization = (WebAppAuthorization) principal;
			String domain = authorization.getDomain() + "-";
			for (String key : super.getKeys(principal)) {
				if (key.startsWith(domain)) {
					list.add(key);
				}
			}
		}
		return list;
	}

}
