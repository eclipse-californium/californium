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
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.zip.GZIPOutputStream;

import org.eclipse.californium.cloud.s3.option.S3ProxyCustomOptions;
import org.eclipse.californium.cloud.s3.proxy.S3ListRequest;
import org.eclipse.californium.cloud.s3.proxy.S3ListResponse;
import org.eclipse.californium.cloud.s3.proxy.S3ListResponse.S3Object;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyRequest;
import org.eclipse.californium.cloud.s3.proxy.S3PutRequest;
import org.eclipse.californium.cloud.s3.proxy.S3Request;
import org.eclipse.californium.cloud.s3.proxy.S3Request.CacheMode;
import org.eclipse.californium.cloud.s3.proxy.S3Response;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Collects data files for archive files.
 * <p>
 * Accumulates the data of single requests of days into an archive file. It is
 * intended to run once a day and appends the last complete day.
 * <p>
 * Format:
 * 
 * <pre>
 * {@code #L<length-of-request-data>#D<date>T<time>Z#I<interval>#C<coap-content-type>#\n}
 * {@code <request data>}
 * {@code #L<length-of-request-data>#D<date>T<time>Z#I<interval>#C<coap-content-type>#\n}
 * {@code <request data>}
 * {@code ...}
 * </pre>
 * 
 * Example: {@code ##L720#D2024-09-27T15:27:03.217Z#I3600#C0#}
 * <p>
 * Only the {@code L} field is mandatory, the others may be not available. The
 * date-time field uses the ISO format, see example. {@code I} contains the
 * expected send interval in seconds indicated by the device using
 * {@link S3ProxyCustomOptions#INTERVAL}, and {@code C} contains the numerical
 * coap content-type option.
 * 
 * The file includes also two custom metadata fields {@link #METADATA_LASTDAY}
 * and {@link #METADATA_DAYS}, which helps to append new days or switch to a new
 * archive.
 * 
 * @since 4.0
 */
public class S3ArchJob extends S3BaseJob {

	private static final Logger LOGGER = LoggerFactory.getLogger(S3ArchJob.class);
	/**
	 * Maximum number of days per archive.
	 */
	private final int maxDaysPerArch;
	/**
	 * Current S3 archive key. May be {@code null}.
	 */
	private volatile String archKey;
	/**
	 * Last date in current archive file. May be {@code null}.
	 */
	private volatile String archLastDate;
	/**
	 * New S3 archive key. May be {@code null}.
	 */
	private volatile String newArchKey;
	/**
	 * Number of days in current archive.
	 */
	private volatile int archDays;

	/**
	 * Creates an archive job.
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
	public S3ArchJob(S3ProxyClient s3Client, String domain, String deviceKey, boolean testOnly,
			S3ProcessorHealth health) {
		super(s3Client, domain, deviceKey, testOnly, health);
		this.maxDaysPerArch = getMaximumDaysPerArchive();
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Starts collecting data files of completed single days into archive file.
	 * 
	 * @param uptoDate Ignored by this job.
	 * @param uptoDay Ignored by this job.
	 */
	@Override
	protected boolean start(String uptoDate, Integer uptoDay, Consumer<Integer> ready) {
		if (!super.start(uptoDate, uptoDay, ready)) {
			return false;
		}
		archDays = 0;
		archLastDate = null;
		if (archKey != null) {
			LOGGER.info("{} {}", domain, archKey);
			s3Client.load(S3Request.builder().key(archKey).cacheMode(CacheMode.NONE).build(),
					(response) -> listNextDays(response));
		} else {
			s3Client.list(S3ListRequest.builder().prefix(deviceKey + ARCH_RESOURCE_NAME).delimiter("/").build(),
					(list) -> {
						try {
							if (list != null) {
								List<S3Object> archs = list.getObjects();
								if (archs.isEmpty()) {
									archKey = null;
									listNextDays(null);
								} else {
									Collections.sort(archs);
									S3Object arch = archs.get(archs.size() - 1);
									archKey = arch.key;
									LOGGER.info("{} {} {}", domain, arch.key, arch.etag);
									s3Client.load(S3Request.builder().key(arch.key).cacheMode(CacheMode.NONE).build(),
											(response) -> listNextDays(response));
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
		return true;
	}

	/**
	 * Lists next days to append to archive.
	 * 
	 * @param arch archive
	 */
	private void listNextDays(S3Response arch) {
		try {
			final ByteArrayOutputStream out = new ByteArrayOutputStream();
			String startAfter = null;
			int maxListDays = maxDaysPerArch + 1;
			if (arch != null) {
				LocalDate lastDay = getLocalDate(arch.getMetadata(), METADATA_LASTDAY);
				Integer days = getInteger(arch.getMetadata(), METADATA_DAYS);
				String base = getBaseArchFromKey(archKey);
				if (lastDay != null && days != null) {
					LOGGER.info("{}: arch {} to {}, {} days", domain, archKey, lastDay, days);
					startAfter = deviceKey + lastDay.toString() + "/";
					if (days < maxDaysPerArch && base != null) {
						try {
							InputStream in = getContentAsStream(arch);
							append(in, out);
							archDays = days;
							maxListDays -= archDays;
							LOGGER.info("{}: search for {} days for arch {} after {}", domain, maxListDays, archKey,
									startAfter);
						} catch (IOException e) {
							LOGGER.warn("Arch-Append-Ex: {} {}", domain, archKey, e);
							out.reset();
						}
					}
				}
			}
			if (out.size() == 0) {
				if (startAfter != null) {
					LOGGER.info("{}: search for {} days for new arch after {}", domain, maxListDays, startAfter);
				} else {
					LOGGER.info("{}: search for {} days for new arch", domain, maxListDays);
				}
			}
			s3Client.list(S3ListRequest.builder().prefix(deviceKey + "2").startAfter(startAfter).maxKeys(maxListDays)
					.delimiter("/").build(), (days) -> {
						if (days != null) {
							listMessagesOfDays(days, out);
						} else {
							ready(-1);
						}
					});
		} catch (RuntimeException ex) {
			ready(-1);
		}
	}

	/**
	 * Lists messages of days.
	 * 
	 * @param daysList list of days
	 * @param out output stream to add messages
	 */
	private void listMessagesOfDays(S3ListResponse daysList, final ByteArrayOutputStream out) {
		try {
			final AtomicInteger dayCounter = new AtomicInteger();
			final List<S3Object> newMessages = new ArrayList<>();
			final List<String> dates = daysList.getPrefixes();
			int count = dates.size();

			addedDays = count;
			if (count == 0) {
				LOGGER.info("{} {} no more days", domain, deviceKey);
				ready(200); // OK
				return;
			}

			Collections.sort(dates);

			boolean removeLast = true;
			String lastKey = dates.get(count - 1);
			String lastDate = getDateAsStringFromKey(lastKey);
			String thisDay = S3Processor.getCurrentDateAsString(0);

			if (lastDate != null) {
				if (lastDate.compareTo(thisDay) < 0) {
					LOGGER.info("{} {}, {} days, more available", domain, deviceKey, count);
					removeLast = (count + archDays) > maxDaysPerArch;
					more = removeLast;
				} else if (lastDate.compareTo(thisDay) > 0) {
					LOGGER.info("{} {}, {} is future data {}", domain, deviceKey);
					addedDays = 0;
					ready(-1);
					return;
				}
			}

			if (removeLast) {
				--count;
				dates.remove(count);
				addedDays = count;
				if (count == 0) {
					ready(200); // OK
					return;
				}
			}

			dayCounter.set(count);

			for (String date : dates) {
				s3Client.list(S3ListRequest.builder().prefix(date).delimiter("/").build(), (messagesOfDay) -> {
					try {
						if (messagesOfDay != null) {
							synchronized (newMessages) {
								newMessages.addAll(messagesOfDay.getObjects());
							}
						}
						if (dayCounter.decrementAndGet() == 0) {
							if (newMessages.isEmpty()) {
								addedDays = 0;
								ready(0);
								return;
							}
							// ready
							archDays += dates.size();
							Collections.sort(newMessages);
							for (S3Object data : newMessages) {
								LOGGER.trace("{} {} {}", domain, data.key, data.etag);
							}
							if (out.size() == 0) {
								String firstKey = newMessages.get(0).key;
								String firstDate = getDateAsStringFromKey(firstKey);
								if (firstDate != null) {
									newArchKey = deviceKey + ARCH_RESOURCE_NAME + firstDate;
								} else {
									LOGGER.warn("No match: {} {}", domain, firstKey);
									ready(-1);
									return;
								}
							} else {
								newArchKey = archKey;
							}
							loadMessages(newMessages, out);
						}
					} catch (RuntimeException ex) {
						ready(-1);
					}
				});
			}
		} catch (RuntimeException ex) {
			ready(-1);
		}
	}

	/**
	 * Loads messages to append.
	 * <p>
	 * When all messages are loaded, write new archive file.
	 * 
	 * @param newMessages sorted list of new messages
	 * @param out output stream to add messages
	 */
	private void loadMessages(final List<S3Object> newMessages, final ByteArrayOutputStream out) {
		final ConcurrentMap<S3Object, S3Response> newData = new ConcurrentHashMap<>();
		final AtomicInteger messageCounter = new AtomicInteger(newMessages.size());
		for (S3Object message : newMessages) {
			s3Client.load(S3Request.builder().key(message.key).cacheMode(CacheMode.NONE).build(), (response) -> {
				try {
					if (response != null) {
						newData.put(message, response);
					}
					if (messageCounter.decrementAndGet() == 0) {
						if (newMessages.size() == newData.size()) {
							appendMessages(newMessages, newData, out);
						} else {
							// not all messages are loaded
							ready(-1);
						}
					}
				} catch (RuntimeException ex) {
					ready(-1);
				}
			});
		}
	}

	/**
	 * Appends new messages to archive.
	 * 
	 * @param newMessages sorted list of new messages
	 * @param newData map of new messages and message contents
	 * @param out output stream to add messages
	 */
	private void appendMessages(List<S3Object> newMessages, Map<S3Object, S3Response> newData,
			ByteArrayOutputStream out) {
		for (S3Object message : newMessages) {
			S3Response response = newData.get(message);
			try {
				StringBuilder head = new StringBuilder("\n#");
				head.append("#L").append(response.getContentLength());
				Matcher matcher = DATE_TIME.matcher(message.key);
				if (matcher.matches()) {
					archLastDate = matcher.group(1);
					head.append("#D").append(archLastDate).append("T").append(matcher.group(2));
					String millis = matcher.group(3);
					if (millis == null) {
						millis = ".000";
					}
					head.append(millis).append("Z");
				}
				Map<String, String> metadata = response.getMetadata();
				if (metadata != null) {
					String interval = metadata.get(S3ProxyRequest.METADATA_INTERVAL);
					if (interval != null) {
						head.append("#I").append(interval);
					}
					String ct = metadata.get(S3ProxyRequest.METADATA_COAP_CONTENT_TYPE);
					if (ct != null) {
						head.append("#C").append(ct);
					}
				}
				head.append("#\n");
				out.write(head.toString().getBytes(StandardCharsets.UTF_8));
				InputStream in = getContentAsStream(response);
				append(in, out);
			} catch (IOException e) {
				LOGGER.warn("Arch-Ex: {} {}", domain, message.key, e);
				ready(-1);
				return;
			} catch (RuntimeException e) {
				LOGGER.warn("Arch-Ex: {} {}", domain, message.key, e);
				ready(-1);
				return;
			}
		}

		boolean compress = s3Client.useCompression();
		String tail = "Z";
		Matcher matcher = INDEX.matcher(newArchKey);
		if (matcher.matches()) {
			tail = matcher.group(1);
		}
		newArchKey = StringUtil.truncateTail(newArchKey, tail);
		if (archDays < maxDaysPerArch) {
			newArchKey += "+" + String.format("%02d", archDays);
		} else {
			newArchKey += "Z";
		}

		if (compress) {
			try {
				ByteArrayOutputStream outCompressed = new ByteArrayOutputStream();
				GZIPOutputStream gzip = new GZIPOutputStream(outCompressed);
				out.writeTo(gzip);
				gzip.finish();
				out = outCompressed;
				newArchKey += ARCH_RESOURCE_ENDING_GZIP;
			} catch (IOException e) {
				compress = false;
			}
		}

		S3PutRequest.Builder builder = S3PutRequest.builder();
		builder.key(newArchKey);

		Map<String, String> meta = new HashMap<>();
		if (archLastDate != null) {
			meta.put(METADATA_LASTDAY, archLastDate);
		}
		meta.put(METADATA_DAYS, Integer.toString(archDays));
		builder.meta(meta);
		builder.contentType(ARCH_CONTENT_TYPE);
		if (compress) {
			builder.contentEncoding(CONTENT_ENCODING_GZIP);
		}
		builder.content(out.toByteArray());
		if (testOnly) {
			LOGGER.info("Arch: {} {} {} {} {}more data availale (test only)", domain, newArchKey, archLastDate,
					archDays, more ? "" : "no ");
			ready(200);
			return;
		}
		s3Client.save(builder.build(), (save) -> {
			if (save != null) {
				if (save.getHttpStatusCode() < 300) {
					LOGGER.info("Arch: {} {} {} {} OK", domain, newArchKey, archLastDate, archDays);
				} else {
					LOGGER.info("Arch: {} {} {}", domain, newArchKey, save.getHttpStatusCode());
				}
				LOGGER.info("Arch: {} {} {}more data availale", domain, deviceKey, more ? "" : "no ");
				boolean delete = false;
				if (archKey != null && INDEX.matcher(archKey).matches()) {
					delete = !archKey.equals(newArchKey);
				}
				if (delete) {
					S3Request.Builder delBuilder = S3Request.builder();
					delBuilder.key(archKey);
					s3Client.delete(delBuilder.build(), (del) -> {
						if (del != null) {
							archKey = newArchKey;
							newArchKey = null;
						}
						ready(save.getHttpStatusCode());
					});
				} else {
					archKey = newArchKey;
					newArchKey = null;
					ready(save.getHttpStatusCode());
				}
			} else {
				ready(-1);
			}
		});
	}
}
