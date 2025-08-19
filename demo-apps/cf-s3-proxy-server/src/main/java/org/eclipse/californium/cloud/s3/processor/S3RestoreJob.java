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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.eclipse.californium.cloud.s3.proxy.S3ListRequest;
import org.eclipse.californium.cloud.s3.proxy.S3ListResponse.S3Object;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyRequest;
import org.eclipse.californium.cloud.s3.proxy.S3PutRequest;
import org.eclipse.californium.cloud.s3.proxy.S3Request;
import org.eclipse.californium.cloud.s3.proxy.S3Request.CacheMode;
import org.eclipse.californium.cloud.s3.proxy.S3Response;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.MediaTypeRegistry.MediaTypeDefintion;
import org.eclipse.californium.elements.util.DataStreamReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Restore last data file from archive.
 * <p>
 * Maintenance job to restore the last data file of a request from the archives.
 * The Web UI use that file to check for the freshest data. The current
 * {@link S3DeleteDaysJob} keeps now the last data file, but versions before
 * accidentally removed them.
 * <p>
 * Maybe also the base for a future export data job.
 * 
 * @since 4.0
 */
public class S3RestoreJob extends S3BaseJob {

	private static final Logger LOGGER = LoggerFactory.getLogger(S3RestoreJob.class);

	private static final byte[] HEADER = "\n##".getBytes();
	private static final byte END = '\n';

	private volatile String lastArchive;

	/**
	 * Creates a job the restore the last data file from archive.
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
	public S3RestoreJob(S3ProxyClient s3Client, String domain, String deviceKey, boolean testOnly,
			S3ProcessorHealth health) {
		super(s3Client, domain, deviceKey, testOnly, health);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Starts restoring the last data from archive.
	 * 
	 * @param uptoDate Ignored by this job.
	 * @param uptoDay Ignored by this job.
	 */
	@Override
	protected boolean start(String uptoDate, Integer uptoDay, Consumer<Integer> ready) {
		if (!super.start(uptoDate, uptoDay, ready)) {
			return false;
		}
		lastArchive = null;
		s3Client.list(S3ListRequest.builder().prefix(deviceKey + "20").delimiter("/").build(), (list) -> {
			try {
				if (list != null) {
					if (list.getPrefixes().isEmpty()) {
						readLastArchive();
					} else {
						ready(200);
					}
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
	 * Read last archive.
	 */
	private void readLastArchive() {
		s3Client.list(S3ListRequest.builder().prefix(deviceKey + ARCH_RESOURCE_NAME).delimiter("/").build(), (list) -> {
			try {
				if (list != null) {
					List<S3Object> archs = list.getObjects();
					if (!archs.isEmpty()) {
						Collections.sort(archs);
						lastArchive = archs.get(archs.size() - 1).key;
						s3Client.load(S3Request.builder().key(lastArchive).cacheMode(CacheMode.NONE).build(),
								(response) -> {
									if (response == null) {
										ready(-1);
										return;
									}
									try {
										parseArchive(response);
									} catch (RuntimeException ex) {
										LOGGER.warn("Process failed!", ex);
										ready(-1);
									}
								});
					} else {
						ready(200);
					}
				} else {
					ready(-1);
				}
			} catch (RuntimeException ex) {
				LOGGER.warn("Process failed!", ex);
				ready(-1);
			}
		});
	}

	/**
	 * Parse archive file.
	 * 
	 * @param response load response
	 */
	private void parseArchive(S3Response response) {
		try {
			InputStream in = getContentAsStream(response);
			DataStreamReader reader = new DataStreamReader(in);
			Data data = null;
			Data last = null;
			while (in.available() > 0 && (data = readNextData(reader)) != null) {
				last = data;
			}
			if (!restoreData(last)) {
				ready(-1);
			}
		} catch (IOException ex) {
			LOGGER.warn("{}: process failed!", lastArchive, ex);
			LOGGER.warn("{}: {} bytes {}", lastArchive, response.getContentLength(), response.getContentEncoding());
			ready(-1);
		} catch (RuntimeException ex) {
			LOGGER.warn("{}: process failed!", lastArchive, ex);
			LOGGER.warn("{}: {} bytes {}", lastArchive, response.getContentLength(), response.getContentEncoding());
			ready(-1);
		}
	}

	/**
	 * Read next data
	 * 
	 * @param reader reader for data
	 * @return next Data
	 */
	private Data readNextData(DataStreamReader reader) {
		byte[] header = reader.readBytes(HEADER.length);
		if (!Arrays.equals(header, HEADER)) {
			throw new IllegalStateException("HEADER \"\\n##\" missing!");
		}
		int len = 0;
		for (int index = 0; index < buffer.length; ++index) {
			byte b = reader.readNextByte();
			if (b == END) {
				len = index;
				break;
			}
			buffer[index] = b;
		}
		if (len == 0) {
			throw new IllegalStateException("END \"\\n\" missing!");
		}
		String line = new String(buffer, 0, len, StandardCharsets.US_ASCII);
		String[] values = line.split("#");
		String lengthValue = values[0];
		if (lengthValue.startsWith("L")) {
			int dataLen = Integer.parseInt(lengthValue.substring(1));
			byte[] payload = reader.readBytes(dataLen);
			return new Data(values, payload);
		} else {
			throw new IllegalStateException("L missing!");
		}
	}

	/**
	 * Restore last data file.
	 * 
	 * @param lastData last data
	 * @return {@code true}, if saving has been started, {@code false} if an
	 *         error occurred preventing to save the data
	 */
	private boolean restoreData(Data lastData) {
		if (lastData == null) {
			return false;
		}
		LOGGER.info("{}: last data {}", lastArchive, lastData);
		String date = null;
		S3PutRequest.Builder builder = S3PutRequest.builder();
		Map<String, String> meta = new HashMap<>();
		for (int index = 1; index < lastData.values.length; ++index) {
			String value = lastData.values[index];
			if (value.startsWith("D")) {
				date = value;
			} else if (value.startsWith("I")) {
				meta.put(S3ProxyRequest.METADATA_INTERVAL, value.substring(1));
			} else if (value.startsWith("C")) {
				value = value.substring(1);
				meta.put(S3ProxyRequest.METADATA_COAP_CONTENT_TYPE, value);
				try {
					int coapContentType = Integer.parseInt(value);
					MediaTypeDefintion mediaType = MediaTypeRegistry.getDefinition(coapContentType);
					if (mediaType != null) {
						builder.contentType(mediaType.getMime());
					}
				} catch (NumberFormatException ex) {
				}
			}
		}
		if (date == null) {
			LOGGER.info("Restore last data for {} failed, missing date {}", lastArchive, lastData);
			return false;
		}
		String day = date.substring(1, 11);
		String time = date.substring(12, 24);
		LOGGER.info("Restore {}{}/{}{}", deviceKey, day, time, testOnly ? " (test only)" : "");
		builder.key(deviceKey + day + "/" + time);
		builder.meta(meta);
		builder.content(lastData.payload);
		if (testOnly) {
			ready(200);
			return true;
		}
		s3Client.save(builder.build(), (response) -> {
			if (response != null) {
				ready(response.getHttpStatusCode());
			} else {
				ready(-1);
			}
		});
		return true;
	}

	private static class Data {

		private final String[] values;
		private final byte[] payload;

		private Data(String[] values, byte[] payload) {
			this.values = values;
			this.payload = payload;
		}

		@Override
		public String toString() {
			return Arrays.toString(values);
		}
	}
}
