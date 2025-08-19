/********************************************************************************
 * Copyright (c) 2025 Contributors to the Eclipse Foundation
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
package org.eclipse.californium.cloud.s3.util;

import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import org.eclipse.californium.cloud.s3.http.Aws4Authorizer.WebAppAuthorization;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Domain statistic manager.
 * <p>
 * Uses sets of statistics per domain.
 * 
 * @since 4.0
 */
public class DomainStatisticManager extends CounterStatisticManager {

	/** The logger. */
	private final Logger LOGGER;
	/**
	 * Title of domain statistic.
	 */
	private final String title;
	/**
	 * Indicates to transfer counters on {@link #dump()}.
	 */
	private final boolean transfer;
	/**
	 * Indicates, that statistic is used.
	 */
	private volatile boolean used = false;

	/**
	 * Creates a domain statistic manager.
	 * 
	 * @param tag tag for associated counter statistic
	 * @param title title for logging
	 * @param transfer {@code true} to transfer the counters on dump
	 * @param logger name of logger
	 */
	public DomainStatisticManager(String tag, String title, boolean transfer, String logger) {
		super(tag);
		this.LOGGER = LoggerFactory.getLogger(logger);
		this.title = title;
		this.transfer = transfer;
	}

	/**
	 * Increments counter value.
	 * 
	 * @param domain domain name
	 * @param name statistics name
	 */
	protected void increment(String domain, String name) {
		SimpleCounterStatistic statistic = getByKey(domain + "-" + name);
		if (statistic != null) {
			used = true;
			statistic.increment();
		}
	}

	/**
	 * Increments counter value by delta.
	 * 
	 * @param domain domain name
	 * @param name statistics name
	 * @param delta value to increment
	 */
	protected void increment(String domain, String name, int delta) {
		SimpleCounterStatistic statistic = getByKey(domain + "-" + name);
		if (statistic != null) {
			used = true;
			statistic.increment(delta);
		}
	}

	/**
	 * Sets counter value.
	 * 
	 * @param domain domain name
	 * @param name statistics name
	 * @param value value to set
	 */
	protected void set(String domain, String name, long value) {
		SimpleCounterStatistic statistic = getByKey(domain + "-" + name);
		if (statistic != null) {
			used = true;
			statistic.set(value);
		}
	}

	@Override
	public boolean isEnabled() {
		return LOGGER.isInfoEnabled();
	}

	@Override
	public boolean useSections() {
		return true;
	}

	@Override
	public void dump() {
		try {
			if (isEnabled() && used) {
				if (LOGGER.isDebugEnabled()) {
					StringBuilder log = new StringBuilder();
					String eol = StringUtil.lineSeparator();
					String head = "   " + tag;
					String head2 = "      ";
					String lastDomain = "";
					log.append(tag).append(title).append(':');
					for (String key : getKeys()) {
						SimpleCounterStatistic counter = getByKey(key);
						String domain = counter.getHead(key);
						if (!lastDomain.equals(domain)) {
							lastDomain = domain;
							log.append(eol).append(head).append("domain: ").append(domain);
						}
						log.append(eol).append(head2).append(counter);
					}
					LOGGER.debug("{}", log);
				}
				if (transfer) {
					transferCounter();
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
