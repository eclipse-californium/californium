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

import java.util.List;
import java.util.function.Consumer;

import org.eclipse.californium.cloud.s3.proxy.S3ListRequest;
import org.eclipse.californium.cloud.s3.proxy.S3ListResponse.S3Object;
import org.eclipse.californium.cloud.s3.proxy.S3ProcessorHealth;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Delete series files.
 * <p>
 * Maintenance job to delete series files though they are obsolete and replaced
 * by archive files.
 * 
 * @since 4.0
 */
public class S3DeleteSeriesJob extends S3BaseJob {

	private static final Logger LOGGER = LoggerFactory.getLogger(S3DeleteSeriesJob.class);

	/**
	 * Create a delete series job.
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
	public S3DeleteSeriesJob(S3ProxyClient s3Client, String domain, String deviceKey, boolean testOnly,
			S3ProcessorHealth health) {
		super(s3Client, domain, deviceKey, testOnly, health);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Starts deleting old series files.
	 * 
	 * @param uptoDate Ignored by this job.
	 * @param uptoDay Ignored by this job.
	 */
	@Override
	protected boolean start(String uptoDate, Integer uptoDay, Consumer<Integer> ready) {
		if (!super.start(uptoDate, uptoDay, ready)) {
			return false;
		}
		s3Client.list(S3ListRequest.builder().prefix(deviceKey + "series-").delimiter("/").build(), (list) -> {
			try {
				if (list != null) {
					List<S3Object> archs = list.getObjects();
					deletes(archs, 0);
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
}
