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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

import org.eclipse.californium.cloud.s3.proxy.S3ListRequest;
import org.eclipse.californium.cloud.s3.proxy.S3ListResponse.S3Object;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;

/**
 * Delete data files.
 * <p>
 * Maintenance job to remove the data files from single requests. Though S3
 * considers a minimum file size for billing (e.g. 128kb), have quite a lot of
 * very small files turns into large billing sizes. If these files are already
 * collected in archive files, it reduces the billing size to remove them.
 * 
 * @since 4.0
 */
public class S3DeleteDaysJob extends S3BaseJob {

	private static final Logger LOGGER = LoggerFactory.getLogger(S3DeleteDaysJob.class);

	/**
	 * Create an delete data files job.
	 * 
	 * @param s3Client S3 client to read the request data and write the archive
	 *            files.
	 * @param domain domain name
	 * @param deviceKey S3 device key
	 * @param testOnly test only, don't save nor delete
	 * @param health S3 processor health. May be {@code null}.
	 * @throws NullPointerException if s3Client, domain or deviceKey is
	 *             {@code null}
	 */
	public S3DeleteDaysJob(S3ProxyClient s3Client, String domain, String deviceKey, boolean testOnly,
			S3ProcessorHealth health) {
		super(s3Client, domain, deviceKey, testOnly, health);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Starts deleting old date/time files.
	 */
	@Override
	protected boolean start(String uptoDate, Integer uptoDay, Consumer<Integer> ready) {
		if (!super.start(uptoDate, uptoDay, ready)) {
			return false;
		}
		s3Client.list(S3ListRequest.builder().prefix(deviceKey + "20").delimiter("/").build(), (list) -> {
			try {
				if (list != null) {
					deleteDays(uptoDate, uptoDay, list.getPrefixes());
				} else {
					ready(-1);
				}
			} catch (RuntimeException ex) {
				LOGGER.warn("Process failed!", ex);
				ready(-1);
			}
		});
		return true;
	}

	/**
	 * Deletes data files
	 * 
	 * @param uptoDate date to stop processing. May be {@code null}.
	 * @param uptoDay last days to stop processing. May be {@code null}.
	 * @param dates list of dates
	 */
	private void deleteDays(String uptoDate, Integer uptoDay, List<String> dates) {
		List<String> filtered = new ArrayList<>(dates.size());
		if (uptoDay != null) {
			int size = dates.size();
			if (size > uptoDay) {
				filtered.addAll(dates.subList(0, size - uptoDay));
			}
		} else {
			for (String date : dates) {
				if (filterDate(date, uptoDate)) {
					filtered.add(date);
				}
			}
		}
		if (filtered.isEmpty()) {
			ready(200);
			return;
		}
		final AtomicInteger dayCounter = new AtomicInteger(filtered.size());
		final List<S3Object> deletes = new ArrayList<>();
		for (String date : filtered) {
			s3Client.list(S3ListRequest.builder().prefix(date).delimiter("/").build(), (list) -> {
				try {
					if (list != null) {
						synchronized (deletes) {
							deletes.addAll(list.getObjects());
						}
					} else {
						ready(-1);
					}
					if (dayCounter.decrementAndGet() == 0 && isBusy()) {
						LOGGER.info("{} delete {} files.", deviceKey, deletes.size());
						Collections.sort(deletes);
						// keep last data
						deletes.remove(deletes.size() - 1);
						deletes(deletes, 0);
					}
				} catch (RuntimeException ex) {
					LOGGER.warn("Process failed!", ex);
					ready(-1);
				}
			});
		}
	}

}
