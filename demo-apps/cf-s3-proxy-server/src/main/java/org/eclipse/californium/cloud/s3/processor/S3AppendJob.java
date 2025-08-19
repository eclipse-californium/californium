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
package org.eclipse.californium.cloud.s3.processor;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.zip.GZIPOutputStream;

import org.eclipse.californium.cloud.s3.proxy.S3ListRequest;
import org.eclipse.californium.cloud.s3.proxy.S3ListResponse.S3Object;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3PutRequest;
import org.eclipse.californium.cloud.s3.proxy.S3Request;
import org.eclipse.californium.cloud.s3.proxy.S3Request.CacheMode;
import org.eclipse.californium.cloud.s3.proxy.S3Response;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Appends archives.
 * <p>
 * Maintenance job used to increase the number of days in past archive file.
 * Switching from uncompressed to compressed archive files works best, if the
 * number of days per files is increased. This job combines the steps to append
 * archive files and compress the resulting files.
 * 
 * @since 4.0
 */
public class S3AppendJob extends S3BaseJob {

	private static final Logger LOGGER = LoggerFactory.getLogger(S3AppendJob.class);
	/**
	 * Maximum number of days per archive.
	 */
	private final int maxDaysPerArch;
	/**
	 * Key of archive to append. May be {@code null}.
	 */
	private volatile S3Object appendArch;
	/**
	 * Content of archive to append. May be {@code null}.
	 */
	private volatile S3Response appendArchResponse;
	/**
	 * Key of last appended archive. May be {@code null}.
	 */
	private volatile String appendArchLastKey;
	/**
	 * Last Date in appended archive. May be {@code null}.
	 */
	private volatile String appendArchLastDate;

	/**
	 * Number of days in current archive.
	 */
	private volatile int archDays;

	/**
	 * Creates an append archives job.
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
	public S3AppendJob(S3ProxyClient s3Client, String domain, String deviceKey, boolean testOnly,
			S3ProcessorHealth health) {
		super(s3Client, domain, deviceKey, testOnly, health);
		this.maxDaysPerArch = getMaximumDaysPerArchive();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Starts appending archive files.
	 * 
	 * @param uptoDate Ignored by this job.
	 * @param uptoDay Ignored by this job.
	 */
	@Override
	protected boolean start(String uptoDate, Integer uptoDay, Consumer<Integer> ready) {
		if (!super.start(uptoDate, uptoDay, ready)) {
			return false;
		}
		archDays = -1;
		appendArch = null;
		appendArchResponse = null;
		s3Client.list(S3ListRequest.builder().prefix(deviceKey + ARCH_RESOURCE_NAME).delimiter("/")
				.startAfter(appendArchLastKey).build(), (list) -> {
					try {
						if (list != null) {
							ByteArrayOutputStream out = new ByteArrayOutputStream();
							List<S3Object> deletes = new ArrayList<>();
							List<S3Object> archs = list.getObjects();
							Collections.sort(archs);
							appendArchives(archs, 0, out, deletes);
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
	 * Appends archives.
	 */
	private void appendArchives(final List<S3Object> archs, int index, final ByteArrayOutputStream out,
			final List<S3Object> deletes) {
		while (index < archs.size()) {
			String key = archs.get(index).key;
			String date = getDateAsStringFromKey(key);
			if (date == null) {
				if (appendArch != null && index + 1 == archs.size()) {
					if (true) {
						saveAppendedArchive(out, deletes);
					}
					// else {
					// deletes.add(archs.get(index));
					// LOGGER.info("Arch: {} {} drop {}!", domain,
					// appendArch.key, deletes);
					// deletes.add(appendArch);
					// deletes(deletes, 0);
					// }
					return;
				}
			} else if (appendArchLastDate == null || appendArchLastDate.compareTo(date) < 0) {
				if (key.endsWith("Z" + ARCH_RESOURCE_ENDING_GZIP) || key.endsWith("Z")) {
					break;
				}
			}
			++index;
		}
		if (index < archs.size()) {
			final S3Object arch = archs.get(index);
			final int nextIndex = index + 1;
			s3Client.load(S3Request.builder().key(arch.key).cacheMode(CacheMode.NONE).build(), (response) -> {
				if (response == null) {
					ready(-1);
					return;
				}
				String lastDate = getString(response.getMetadata(), METADATA_LASTDAY);
				Integer days = getInteger(response.getMetadata(), METADATA_DAYS);
				if (days == null) {
					LOGGER.warn("Arch: {} {} append failed, no days in meta-data!", domain, arch.key);
					ready(-1);
				}
				if (lastDate == null) {
					LOGGER.warn("Arch: {} {} append failed, no last-date in meta-data!", domain, arch.key);
					ready(-1);
				}
				appendArchLastKey = arch.key;
				appendArchLastDate = lastDate;
				if (archDays < 0) {
					if (days >= maxDaysPerArch) {
						// next
						LOGGER.info("Arch: {} {} already full!", domain, arch.key);
						appendArchives(archs, nextIndex, out, deletes);
						return;
					}
					appendArch = arch;
					appendArchResponse = response;
					archDays = days;
					LOGGER.info("Arch: {} {} {} days, start append.", domain, arch.key, days);
				} else {
					LOGGER.info("Arch: {} {} {} append {} days.", domain, arch.key, archDays, days);
					archDays += days;
					deletes.add(arch);
				}
				more = nextIndex < archs.size();

				try {
					InputStream in = getContentAsStream(response);
					append(in, out);
					if (!more) {
						LOGGER.info("Arch: {} {} {} no more days.", domain, arch.key, archDays);
					} else if (archDays < maxDaysPerArch) {
						LOGGER.info("Arch: {} {} {} append more days.", domain, arch.key, archDays);
						appendArchives(archs, nextIndex, out, deletes);
						return;
					} else {
						LOGGER.info("Arch: {} {} {} full.", domain, arch.key, archDays);
					}
					saveAppendedArchive(out, deletes);
				} catch (IOException e) {
					LOGGER.warn("Arch-append: {} {}", domain, arch.key, e);
					ready(-1);
				} catch (RuntimeException e) {
					LOGGER.warn("Arch-append: {} {}", domain, arch.key, e);
					ready(-1);
				}
			});
		} else {
			ready(200);
		}
	}

	/**
	 * Saves appended archive.
	 * <p>
	 * Included archive are deleted after successful saving.
	 * 
	 * @param out appended archive content
	 * @param deletes archives to delete
	 */
	private void saveAppendedArchive(ByteArrayOutputStream out, final List<S3Object> deletes) {
		// ready
		String key = StringUtil.truncateTail(appendArch.key, ARCH_RESOURCE_ENDING_GZIP);
		ByteArrayOutputStream outAppend = out;
		boolean compress = s3Client.useCompression();
		if (compress) {
			try {
				outAppend = new ByteArrayOutputStream();
				GZIPOutputStream gzip = new GZIPOutputStream(outAppend);
				out.writeTo(gzip);
				gzip.finish();
				key += ARCH_RESOURCE_ENDING_GZIP;
			} catch (IOException e) {
				outAppend = out;
				compress = false;
				LOGGER.info("Arch: {} {} {} days.", domain, key, archDays, e);
			}
		}
		Map<String, String> meta = new HashMap<>();
		meta.put(METADATA_LASTDAY, appendArchLastDate);
		meta.put(METADATA_DAYS, Integer.toString(archDays));

		S3PutRequest.Builder builder = S3PutRequest.builder();
		final String archKey = key;
		builder.key(archKey);
		builder.meta(meta);
		builder.contentType(appendArchResponse.getContentType());
		if (compress) {
			builder.contentEncoding(CONTENT_ENCODING_GZIP);
		}
		builder.content(outAppend.toByteArray());
		LOGGER.info("Arch: {} {} {} days. del {}{}", domain, archKey, archDays, deletes,
				testOnly ? " (test only)" : "");

		if (testOnly) {
			ready(200);
			return;
		}
		s3Client.save(builder.build(), (save) -> {
			if (save != null) {
				if (save.getHttpStatusCode() < 300) {
					LOGGER.info("Arch: {} {} appended", domain, archKey);
					deletes(deletes, 0);
					return;
				} else {
					LOGGER.info("Arch: {} {} append failed {}", domain, archKey, save.getHttpStatusCode());
				}
			} else {
				LOGGER.info("Arch: {} {} append failed, not saved!", domain, archKey);
			}
			ready(-1);
		});
	}
}
