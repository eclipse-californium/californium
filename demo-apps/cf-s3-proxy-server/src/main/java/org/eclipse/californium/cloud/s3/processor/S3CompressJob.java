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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.zip.GZIPOutputStream;

import org.eclipse.californium.cloud.s3.proxy.S3ListRequest;
import org.eclipse.californium.cloud.s3.proxy.S3ListResponse;
import org.eclipse.californium.cloud.s3.proxy.S3ListResponse.S3Object;
import org.eclipse.californium.cloud.s3.proxy.S3ProcessorHealth;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3PutRequest;
import org.eclipse.californium.cloud.s3.proxy.S3Request;
import org.eclipse.californium.cloud.s3.proxy.S3Request.CacheMode;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Compress archives.
 * <p>
 * Maintenance job to compress archives. {@link S3AppendJob} will additionally
 * append several archive to one and compress the outcome.
 * 
 * @since 4.0
 */
public class S3CompressJob extends S3BaseJob {

	private static final Logger LOGGER = LoggerFactory.getLogger(S3CompressJob.class);

	/**
	 * Creates an compress job.
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
	public S3CompressJob(S3ProxyClient s3Client, String domain, String deviceKey, boolean testOnly,
			S3ProcessorHealth health) {
		super(s3Client, domain, deviceKey, testOnly, health);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Starts compressing archive files.
	 * 
	 * @param uptoDate Ignored by this job.
	 * @param uptoDay Ignored by this job.
	 */
	@Override
	protected boolean start(String uptoDate, Integer uptoDay, Consumer<Integer> ready) {
		if (!super.start(uptoDate, uptoDay, ready)) {
			return false;
		}
		more = false;
		addedDays = -1;
		s3Client.list(S3ListRequest.builder().prefix(deviceKey + ARCH_RESOURCE_NAME).delimiter("/").build(), (list) -> {
			try {
				if (list != null) {
					List<S3Object> archs = list.getObjects();
					Collections.sort(archs);
					compressArchives(archs, 0);
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
	 * Compress archives.
	 * 
	 * @param archs list of archives
	 * @param index index in list
	 */
	private void compressArchives(final List<S3Object> archs, int index) {
		while (index < archs.size()) {
			String key = archs.get(index).key;
			if (!key.endsWith(ARCH_RESOURCE_ENDING_GZIP)) {
				if (key.endsWith("Z") || INDEX.matcher(key).matches()) {
					if (!S3ListResponse.hasKey(archs, key + ARCH_RESOURCE_ENDING_GZIP)) {
						break;
					}
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
				if (!response.hasContentEncoding(CONTENT_ENCODING_GZIP)) {
					try {
						ByteArrayOutputStream out = new ByteArrayOutputStream();
						GZIPOutputStream gzip = new GZIPOutputStream(out);
						append(response.getContentAsStream(), gzip);
						gzip.finish();

						String key = arch.key;
						Matcher matcher = INDEX.matcher(key);
						if (matcher.matches()) {
							String tail = matcher.group(1).substring(1);
							key = StringUtil.truncateTail(key, tail);
							try {
								int days = Integer.parseInt(tail);
								key += String.format("%02d", days);
							} catch (NumberFormatException ex) {
								LOGGER.info("{} is no number!", tail);
								ready(-1);
								return;
							}
						}

						final String archKey = key + ARCH_RESOURCE_ENDING_GZIP;
						S3PutRequest.Builder builder = S3PutRequest.builder();
						builder.key(archKey);
						builder.meta(response.getMetadata());
						builder.contentType(response.getContentType());
						builder.contentEncoding(CONTENT_ENCODING_GZIP);
						builder.content(out.toByteArray());
						if (testOnly) {
							compressArchives(archs, nextIndex);
							return;
						}

						s3Client.save(builder.build(), (save) -> {
							if (save != null) {
								if (save.getHttpStatusCode() < 300) {
									LOGGER.info("Arch: {} {} compressed", domain, archKey);
								} else {
									LOGGER.info("Arch: {} {} compression failed {}", domain, archKey,
											save.getHttpStatusCode());
								}
								S3Request.Builder delBuilder = S3Request.builder();
								delBuilder.key(arch.key);
								s3Client.delete(delBuilder.build(), (del) -> {
									if (del != null && archs.remove(arch)) {
										archs.add(nextIndex - 1, new S3Object(archKey, ""));
									}
									compressArchives(archs, nextIndex);
								});
							} else {
								compressArchives(archs, nextIndex);
							}
						});
					} catch (IOException e) {
						ready(-1);
					}
				} else {
					compressArchives(archs, nextIndex);
				}
			});
		} else {
			if (testOnly) {
				ready(200);
				return;
			}
			deleteArchs(archs, 0);
		}
	}

	/**
	 * Delete uncompressed archives with compressed version.
	 * 
	 * @param archs list of archives
	 * @param index index in list
	 */
	private void deleteArchs(final List<S3Object> archs, int index) {
		String lastBaseKey = null;
		List<S3Object> deletes = new ArrayList<>();
		while (index < archs.size()) {
			S3Object object = archs.get(index);
			String key = object.key;
			lastBaseKey = null;
			if (key.endsWith("Z")) {
				if (S3ListResponse.hasKey(archs, key + ARCH_RESOURCE_ENDING_GZIP)) {
					deletes.add(object);
				}
			} else if (!key.endsWith("Z" + ARCH_RESOURCE_ENDING_GZIP)) {
				String baseKey = getBaseArchFromKey(key);
				if (baseKey != null) {
					if (baseKey.endsWith(ARCH_RESOURCE_ENDING_GZIP)) {
						LOGGER.warn("S3-arch: {} {}", domain, key);
						deletes.add(object);
					} else {
						String keyZ = baseKey + "Z";
						if (S3ListResponse.hasKey(archs, keyZ)
								|| S3ListResponse.hasKey(archs, keyZ + ARCH_RESOURCE_ENDING_GZIP)) {
							deletes.add(object);
						} else {
							lastBaseKey = baseKey;
						}
					}
				}
			}
			++index;
		}
		if (lastBaseKey != null) {
			index -= 2;
			while (index >= 0) {
				S3Object object = archs.get(index);
				String baseKey = getBaseArchFromKey(object.key);
				if (!lastBaseKey.equals(baseKey)) {
					break;
				}
				deletes.add(object);
				--index;
			}
		}
		deletes(deletes, 0);
	}

}
