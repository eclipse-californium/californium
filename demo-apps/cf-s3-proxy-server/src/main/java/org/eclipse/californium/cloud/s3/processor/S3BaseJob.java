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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import org.eclipse.californium.cloud.s3.proxy.S3DeletesRequest;
import org.eclipse.californium.cloud.s3.proxy.S3ListResponse.S3Object;
import org.eclipse.californium.cloud.s3.proxy.S3ProcessorHealth;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3Response;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Base for S3 processing jobs.
 * 
 * @since 4.0
 */
public class S3BaseJob {

	private final Logger LOGGER = LoggerFactory.getLogger(getClass());
	/**
	 * Maximum days per archive file.
	 */
	private static final int DAYS_PER_ARCH = 7;
	/**
	 * Maximum days per gzip archive file.
	 */
	private static final int DAYS_PER_ARCH_GZIP = 28;
	/**
	 * Maximum objects to delete by list.
	 */
	protected static final int MAX_DELETES = 500;
	/**
	 * Prefix for archive file name.
	 */
	protected static final String ARCH_RESOURCE_NAME = "arch-";
	/**
	 * Suffix for compressed archive file name.
	 */
	protected static final String ARCH_RESOURCE_ENDING_GZIP = ".gz";
	/**
	 * Content-type for archive file.
	 */
	protected static final String ARCH_CONTENT_TYPE = "application/octet-stream";
	/**
	 * Content-encoding gzip.
	 */
	protected static final String CONTENT_ENCODING_GZIP = "gzip";
	/**
	 * Name of metadata field for the last day contained in the archive file.
	 */
	protected static final String METADATA_LASTDAY = "lastday";
	/**
	 * Name of metadata field for the number of days contained in the archive
	 * file.
	 */
	protected static final String METADATA_DAYS = "days";
	/**
	 * Patter for keys with ISO-date and time.
	 */
	protected static final Pattern DATE_TIME = Pattern
			.compile(".*/([0-9]{4}-[0-1][0-9]-[0-3][0-9])/([0-2][0-9]:[0-5][0-9]:[0-5][0-9])(\\.[0-9]{3})?$");

	/**
	 * Patter for keys with index ending.
	 */
	protected static final Pattern INDEX = Pattern.compile(".*(\\+[0-9]+(\\" + ARCH_RESOURCE_ENDING_GZIP + ")?)$");

	/**
	 * Patter for keys with ISO-date and optional time.
	 */
	private static final Pattern DATE = Pattern
			.compile(".*/([0-9]{4}-[0-1][0-9]-[0-3][0-9])/(([0-2][0-9]:[0-5][0-9]:[0-5][0-9])(\\.[0-9]{3})?)?$");

	/**
	 * Patter for keys with ISO-date and optional time.
	 */
	private static final Pattern ARCH_DATE = Pattern
			.compile(".*arch-([0-9]{4}-[0-1][0-9]-[0-3][0-9])Z(\\" + ARCH_RESOURCE_ENDING_GZIP + ")?$");

	/**
	 * S3 processing health. May be {@code null}.
	 */
	private final S3ProcessorHealth health;
	/**
	 * S3 client to read the request data and write the archive files.
	 */
	protected final S3ProxyClient s3Client;
	/**
	 * Domain name.
	 */
	protected final String domain;
	/**
	 * S3 device key.
	 * <p>
	 * Already terminated with "/".
	 */
	protected final String deviceKey;
	/**
	 * Test only.
	 */
	protected final boolean testOnly;
	/**
	 * Buffer to copy and append S3 files.
	 */
	protected final byte[] buffer = new byte[8192];
	/**
	 * Busy indication.
	 */
	private final AtomicReference<Consumer<Integer>> busy = new AtomicReference<>();
	/**
	 * Number of added days in this run.
	 */
	protected volatile int addedDays;
	/**
	 * Indicates more days to process next time.
	 */
	protected volatile boolean more;

	/**
	 * Creates an device archive.
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
	protected S3BaseJob(S3ProxyClient s3Client, String domain, String deviceKey, boolean testOnly,
			S3ProcessorHealth health) {
		if (s3Client == null) {
			throw new NullPointerException("s3client must not be null!");
		}
		if (domain == null) {
			throw new NullPointerException("domain must not be null!");
		}
		if (deviceKey == null) {
			throw new NullPointerException("deviceKey must not be null!");
		}
		this.s3Client = s3Client;
		this.domain = domain;
		this.deviceKey = deviceKey;
		this.testOnly = testOnly;
		this.health = health;
	}

	/**
	 * Indicates, that there are more days to be appended in the next run.
	 * 
	 * @return {@code true}, if there are more days to append.
	 */
	public boolean hasMore() {
		return more;
	}

	/**
	 * Indicates, that this job is currently active.
	 * 
	 * @return {@code true}, if job is active.
	 */
	public boolean isBusy() {
		return busy.get() != null;
	}

	/**
	 * Gets maximum number of days per archive.
	 * <p>
	 * Uses {@link #DAYS_PER_ARCH} for uncompressed archives, and
	 * {@link #DAYS_PER_ARCH_GZIP} for compressed ones.
	 * 
	 * @return maximum number of days per archive
	 */
	protected int getMaximumDaysPerArchive() {
		return s3Client.useCompression() ? DAYS_PER_ARCH_GZIP : DAYS_PER_ARCH;
	}

	/**
	 * Reports processing ready.
	 * 
	 * @param result processing result as http code. {@code -1} indicates a
	 *            generic failure.
	 * @return {@code true}, if this call ends processing, {@code false}, if
	 *         processing was already finished.
	 */
	protected boolean ready(int result) {
		Consumer<Integer> ready = busy.getAndSet(null);
		if (ready != null) {
			if (health != null) {
				if (200 <= result && result < 300) {
					health.processedDay(domain, addedDays);
				} else {
					health.processedDay(domain, -1);
				}
			}
			if (result < 200 || 300 <= result) {
				more = false;
			}
			ready.accept(result);
		}
		return ready != null;
	}

	/**
	 * Starts processing.
	 * 
	 * @param uptoDate date to stop processing. May be {@code null}.
	 * @param uptoDay last days to stop processing. May be {@code null}.
	 * @param ready consumer for result.
	 * @return {@code true}, if this call start processing, {@code false}, if
	 *         processing was already started.
	 */
	protected boolean start(String uptoDate, Integer uptoDay, Consumer<Integer> ready) {
		boolean res = busy.compareAndSet(null, ready);
		if (res) {
			more = false;
			addedDays = -1;
		}
		return res;
	}

	/**
	 * Appends input stream to output stream.
	 * 
	 * @param in input stream with data to append
	 * @param out output stream to append data to
	 * @return number of bytes appended.
	 * @throws IOException if an i/o error occurred
	 */
	protected int append(InputStream in, OutputStream out) throws IOException {
		int res = 0;
		int len;

		while ((len = in.read(buffer)) >= 0) {
			if (len > 0) {
				res += len;
				out.write(buffer, 0, len);
			}
		}
		return res;
	}

	/**
	 * Deletes files.
	 * 
	 * @param files list of files to delete
	 * @param index index to start the delete
	 */
	protected void deletes(final List<S3Object> files, final int index) {
		if (testOnly) {
			LOGGER.info("Arch: {} {} deletes (test only).", domain, files.size());
			ready(200);
			return;
		}
		if (index < files.size()) {
			S3DeletesRequest.Builder delBuilder = S3DeletesRequest.builder();
			int left = Math.min(files.size() - index, MAX_DELETES);
			delBuilder.deletes(files.subList(index, index + left));
			s3Client.deletes(delBuilder.build(), (del) -> {
				deletes(files, index + left);
			});
		} else {
			ready(200);
		}
	}

	/**
	 * Filters by date.
	 * 
	 * @param key key with date to filter
	 * @param end end date. May be {@code null}
	 * @return {@code true}, if key is before or at end, {@code false}, if key
	 *         is after end
	 */
	protected boolean filterDate(String key, String end) {
		String date = getDateAsStringFromKey(key);
		return date != null && (end == null || date.compareTo(end) <= 0);
	}

	/**
	 * Gets date as string from S3 key.
	 * 
	 * @param key S3 key
	 * @return date as string, or {@code null}, if key doesn't match the date
	 *         pattern.
	 */
	protected String getDateAsStringFromKey(String key) {
		Matcher matcher = DATE.matcher(key);
		if (!matcher.matches()) {
			matcher = ARCH_DATE.matcher(key);
		}
		if (matcher.matches()) {
			return matcher.group(1);
		} else {
			LOGGER.info("{} is no date-key!", key);
			return null;
		}

	}

	/**
	 * Gets archive base key.
	 * <p>
	 * Temporary archives uses names as {@code arch-2025-08-01+08.gz} or
	 * {@code arch-2025-08-01+08}. This function removes the tail and results in
	 * {@code arch-2025-08-01}.
	 * 
	 * @param key S3 key
	 * @return base key
	 */
	protected String getBaseArchFromKey(String key) {
		Matcher matcher = INDEX.matcher(key);
		if (matcher.matches()) {
			return StringUtil.truncateTail(key, matcher.group(1));
		}
		return null;
	}

	/**
	 * Gets content as stream.
	 * <p>
	 * Uncompress content, if compressed.
	 * 
	 * @param response S3 response
	 * @return the content as input stream
	 * @throws IOException if an i/o error occurred
	 */
	protected InputStream getContentAsStream(S3Response response) throws IOException {
		InputStream in = response.getContentAsStream();
		if (in != null && response.hasContentEncoding(CONTENT_ENCODING_GZIP)) {
			return new GZIPInputStream(in);
		}
		return in;
	}

	/**
	 * Gets local date from value.
	 * 
	 * @param name name of value (for logging)
	 * @param value value
	 * @return local date, or {@code null}, if value is not a date.
	 */
	protected LocalDate getLocalDate(String name, String value) {
		if (value != null) {
			try {
				return LocalDate.parse(value);
			} catch (DateTimeParseException ex) {
				LOGGER.info("{}={} is no date!", name, value);
			}
		}
		return null;
	}

	/**
	 * Gets string value from S3 metadata.
	 * 
	 * @param meta map with metadata
	 * @param name name of metadata
	 * @return string value, or {@code null}, if not available.
	 */
	protected String getString(Map<String, String> meta, String name) {
		if (meta != null) {
			return meta.get(name);
		}
		return null;
	}

	/**
	 * Gets integer value from S3 metadata.
	 * 
	 * @param meta map with metadata
	 * @param name name of metadata
	 * @return integer value, or {@code null}, if not available or not a number.
	 */
	protected Integer getInteger(Map<String, String> meta, String name) {
		if (meta != null) {
			String value = meta.get(name);
			if (value != null) {
				try {
					return Integer.parseInt(value);
				} catch (NumberFormatException ex) {
					LOGGER.info("{}={} is no number!", name, value);
				}
			}
		}
		return null;
	}

	/**
	 * Gets date value from S3 metadata.
	 * 
	 * @param meta map with metadata
	 * @param name name of metadata
	 * @return local date, or {@code null}, if not available or not a date.
	 */
	protected LocalDate getLocalDate(Map<String, String> meta, String name) {
		if (meta != null) {
			String value = meta.get(name);
			if (value != null) {
				return getLocalDate(name, value);
			}
		}
		return null;
	}

}
