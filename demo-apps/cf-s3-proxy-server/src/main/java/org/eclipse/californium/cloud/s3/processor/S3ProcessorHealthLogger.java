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
package org.eclipse.californium.cloud.s3.processor;

import java.util.Set;

import org.eclipse.californium.cloud.s3.util.DomainStatisticManager;
import org.eclipse.californium.elements.util.SimpleCounterStatistic;

/**
 * S3 processor health manager.
 * 
 * @since 3.13
 */
public class S3ProcessorHealthLogger extends DomainStatisticManager implements S3ProcessorHealth {

	private static final String PROCESSING = "processing-devices";
	private static final String SUCCESS = "processed-days";
	private static final String FAILURE = "process-failures";

	/**
	 * Creates a S3 processor health logger.
	 * 
	 * @param tag tag for associated counter statistic
	 * @param domains set of domain names
	 */
	public S3ProcessorHealthLogger(String tag, Set<String> domains) {
		super(tag, "s3-processor-statistic", false, S3Processor.class.getName() + ".health");
		for (String domain : domains) {
			String head = domain + "-";
			add(head, new SimpleCounterStatistic(PROCESSING, align));
			add(head, new SimpleCounterStatistic(SUCCESS, align));
			add(head, new SimpleCounterStatistic(FAILURE, align));
		}
	}

	@Override
	public void processedDay(String domain, int days) {
		String name = days >= 0 ? SUCCESS : FAILURE;
		if (days < 0) {
			days = 1;
		}
		increment(domain, name, days);
	}

	@Override
	public void processingDevices(String domain, int devices) {
		set(domain, PROCESSING, devices);
	}
}
