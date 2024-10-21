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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.LocalDate;
import java.time.LocalTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.eclipse.californium.cloud.BaseServer;
import org.eclipse.californium.cloud.s3.S3ProxyServer;
import org.eclipse.californium.cloud.s3.option.S3ProxyCustomOptions;
import org.eclipse.californium.cloud.s3.proxy.S3ListResponse.S3Object;
import org.eclipse.californium.cloud.s3.proxy.S3Request.CacheMode;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * S3 processor.
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
 * {@link S3ProxyCustomOptions#INTERVAL}, and {@code C} contains the
 * numerical coap content-type option.
 * 
 * The file includes also two custom metadata fields {@link #METADATA_LASTDAY}
 * and {@link #METADATA_DAYS}, which helps to append new days or switch to a new
 * archive.
 * 
 * @since 3.13
 */
public class S3Processor {

	private static final Logger LOGGER = LoggerFactory.getLogger(S3Processor.class);

	/**
	 * Maximum days per archive file.
	 */
	public static final int DAYS_PER_ARCH = 7;

	/**
	 * S3-key prefix to list devices.
	 */
	public static final String RESOURCE_NAME = "devices/";
	/**
	 * Prefix for archive file name.
	 */
	public static final String ARCH_RESOURCE_NAME = "arch-";
	/**
	 * Content-type for archive file.
	 */
	public static final String ARCH_CONTENT_TYPE = "application/octet-stream";
	/**
	 * Patter for keys with ISO-date and optional time.
	 */
	private static final Pattern DATE = Pattern
			.compile(".*/([0-9]{4}-[0-1][0-9]-[0-3][0-9])/(([0-2][0-9]:[0-5][0-9]:[0-5][0-9])(\\.[0-9]{3})?)?$");

	/**
	 * Patter for keys with ISO-date and time.
	 */
	private static final Pattern DATE_TIME = Pattern
			.compile(".*/([0-9]{4}-[0-1][0-9]-[0-3][0-9])/([0-2][0-9]:[0-5][0-9]:[0-5][0-9])(\\.[0-9]{3})?$");

	/**
	 * Patter for keys with index ending.
	 */
	private static final Pattern INDEX = Pattern.compile(".*(\\+[0-9]+)$");

	/**
	 * Name of metadata field for the last day contained in the archive file.
	 */
	public static final String METADATA_LASTDAY = "lastday";
	/**
	 * Name of metadata field for the number of days contained in the archive
	 * file.
	 */
	public static final String METADATA_DAYS = "days";
	/**
	 * S3 clients provider to read the request data and write the archive files.
	 */
	private final S3ProxyClientProvider s3Clients;
	/**
	 * S3 processing health. May be {@code null}.
	 */
	private final S3ProcessorHealth health;
	/**
	 * S3 statistics manager. Set from {@link #health}, if that is a
	 * {@link CounterStatisticManager} . May be {@code null}.
	 */
	private final CounterStatisticManager statistics;
	/**
	 * Map of jobs per domain.
	 */
	private final ConcurrentHashMap<String, LeastRecentlyUpdatedCache<String, DeviceArchive>> domainArchs;
	/**
	 * Initial delay (after start) in seconds.
	 * 
	 * @see S3ProxyServer#S3_PROCESSING_INITIAL_DELAY
	 */
	private final long processInitialDelayInSeconds;
	/**
	 * Daily process time in seconds.
	 * <p>
	 * The intended way to process the data accumulation is to run that once a
	 * day. If this field contains a value larger than {@code 0}, that defines
	 * the time after GMT midnight to start the processing. A value of {@code 0}
	 * disables this schedule.
	 * <p>
	 * This value has precedence over {@link #processIntervalInSeconds}.
	 * 
	 * @see S3ProxyServer#S3_PROCESSING_DAILY_TIME
	 */
	private final long processDailyTimeInSeconds;
	/**
	 * Process interval in seconds.
	 * <p>
	 * The intended way to process the data accumulation is to run that once a
	 * day. If {@link #processDailyTimeInSeconds} contains 0, this field defines
	 * the interval in seconds to start the processing. A value of {@code 0}
	 * disables this schedule.
	 * 
	 * @see S3ProxyServer#S3_PROCESSING_INTERVAL
	 */
	private final long processIntervalInSeconds;
	/**
	 * Minutes to grant keeping the device archive data in volatile memory.
	 */
	private final long minutes;
	/**
	 * Maximum number of device to keep the archive data in volatile memory.
	 */
	private final int maxDevices;
	/**
	 * Minimum number of device to keep the archive data in volatile memory.
	 */
	private final int minDevices;
	/**
	 * Scheduler for jobs.
	 */
	private final ScheduledExecutorService scheduler;
	/**
	 * Current scheduled job.
	 */
	private final AtomicReference<ScheduledFuture<?>> job = new AtomicReference<>();
	/**
	 * Busy indicator.
	 */
	private final AtomicBoolean busy = new AtomicBoolean();

	/**
	 * List of current domains.
	 */
	private volatile List<String> domains;

	/**
	 * Create S3 processor.
	 * 
	 * @param config configuration
	 * @param s3Clients S3 clients provider to read the request data and write
	 *            the archive files.
	 * @param health S3 processor health. May be {@code null}.
	 * @param scheduler scheduler for S3 jobs.
	 * @throws NullPointerException if config, s3Clients, or scheduler is
	 *             {@code null}
	 */
	public S3Processor(Configuration config, S3ProxyClientProvider s3Clients, S3ProcessorHealth health,
			ScheduledExecutorService scheduler) {
		if (config == null) {
			throw new NullPointerException("config must not be null!");
		}
		if (s3Clients == null) {
			throw new NullPointerException("s3client must not be null!");
		}
		if (scheduler == null) {
			throw new NullPointerException("scheduler must not be null!");
		}
		this.s3Clients = s3Clients;
		this.health = health;
		this.statistics = (health instanceof CounterStatisticManager) ? (CounterStatisticManager) health : null;
		this.scheduler = scheduler;
		this.processInitialDelayInSeconds = config.get(S3ProxyServer.S3_PROCESSING_INITIAL_DELAY, TimeUnit.SECONDS);
		this.processIntervalInSeconds = config.get(S3ProxyServer.S3_PROCESSING_INTERVAL, TimeUnit.SECONDS);
		this.processDailyTimeInSeconds = config.get(S3ProxyServer.S3_PROCESSING_DAILY_TIME, TimeUnit.SECONDS);
		this.domainArchs = new ConcurrentHashMap<>();

		this.minutes = config.get(BaseServer.CACHE_STALE_DEVICE_THRESHOLD, TimeUnit.MINUTES);
		this.maxDevices = config.get(BaseServer.CACHE_MAX_DEVICES);
		int minDevices = this.maxDevices / 10;
		if (minDevices < 100) {
			minDevices = this.maxDevices;
		}
		this.minDevices = minDevices;
	}

	/**
	 * Start scheduling.
	 */
	public void start() {
		if (processDailyTimeInSeconds > 0) {
			ScheduledFuture<?> previous = job.getAndSet(this.scheduler.schedule(new Runnable() {

				@Override
				public void run() {
					process();
					LocalTime now = LocalTime.now(Clock.systemUTC());
					long dayInSeconds = TimeUnit.DAYS.toSeconds(1);
					int secondOfDay = now.toSecondOfDay();
					long delta = processDailyTimeInSeconds - secondOfDay;
					if (delta < 0) {
						delta += dayInSeconds;
					}
					scheduleProcessing(delta, dayInSeconds, TimeUnit.SECONDS);
				}
			}, processInitialDelayInSeconds, TimeUnit.SECONDS));
			if (previous != null) {
				previous.cancel(false);
			}
		} else if (processIntervalInSeconds > 0) {
			scheduleProcessing(processInitialDelayInSeconds, processIntervalInSeconds, TimeUnit.SECONDS);
		}
	}

	/**
	 * Schedule processing.
	 * 
	 * @param initialDelay initial delay
	 * @param interval interval
	 * @param unit time unit
	 */
	private void scheduleProcessing(long initialDelay, long interval, TimeUnit unit) {
		ScheduledFuture<?> previous = job.getAndSet(this.scheduler.scheduleAtFixedRate(new Runnable() {

			@Override
			public void run() {
				process();
			}
		}, initialDelay, interval, unit));
		if (previous != null) {
			previous.cancel(false);
		}
	}

	/**
	 * Stop scheduled processing.
	 */
	public void stop() {
		ScheduledFuture<?> previous = job.getAndSet(null);
		if (previous != null) {
			previous.cancel(false);
		}
	}

	/**
	 * Stop scheduled processing and clear archive data cache.
	 */
	public void destroy() {
		stop();
		for (LeastRecentlyUpdatedCache<String, DeviceArchive> domain : domainArchs.values()) {
			domain.clear();
		}
		domainArchs.clear();
	}

	/**
	 * Reports, when processing is ready.
	 * 
	 * @return {@code true}, if this call ends processing, {@code false}, if
	 *         processing was already finished.
	 */
	private boolean ready() {
		return busy.compareAndSet(true, false);
	}

	/**
	 * Execute a process run.
	 * <p>
	 * List all devices of all domains and append new data to the archive files.
	 * 
	 * @return {@code true}, if this call start processing, {@code false}, if
	 *         processing was already started.
	 */
	public boolean process() {
		boolean res = busy.compareAndSet(false, true);
		if (res) {
			try {
				if (statistics != null) {
					statistics.transferCounter();
				}
				List<DeviceArchive> jobs = new ArrayList<>();
				domains = new ArrayList<>(s3Clients.getDomains());
				listDevicesPerDomain(0, jobs);
			} catch (RuntimeException ex) {
				ready();
			}
		}
		return res;
	}

	/**
	 * List device of a domain.
	 * 
	 * @param index index of domain in {@link #domains}.
	 * @param jobs list of jobs to add the jobs for each device.
	 */
	private void listDevicesPerDomain(final int index, final List<DeviceArchive> jobs) {
		if (busy.get()) {
			if (index < domains.size()) {
				String domain = domains.get(index);
				LeastRecentlyUpdatedCache<String, DeviceArchive> cache = domainArchs.get(domain);
				if (cache == null) {
					cache = new LeastRecentlyUpdatedCache<>(minDevices, maxDevices, minutes, TimeUnit.MINUTES);
					domainArchs.put(domain, cache);
				}
				final LeastRecentlyUpdatedCache<String, DeviceArchive> domainCache = cache;
				final S3ProxyClient s3Client = s3Clients.getProxyClient(domain);
				s3Client.list(S3ListRequest.builder().key(RESOURCE_NAME).delimiter("/").build(), (t) -> {
					try {
						if (t != null) {
							List<String> devices = t.getPrefixes();
							for (String device : devices) {
								LOGGER.info(device);
								DeviceArchive arch = domainCache.get(device);
								if (arch == null) {
									arch = new DeviceArchive(s3Client, health, domain, device);
									domainCache.put(device, arch);
								}
								jobs.add(arch);
							}
						}
						listDevicesPerDomain(index + 1, jobs);
					} catch (RuntimeException ex) {
						ready();
					}
				});
			} else {
				countPendingDevicesPerDomain(jobs);
				processJobs(jobs, 0);
			}
		}
	}

	/**
	 * Reports a statistic of pending device per domain.
	 * 
	 * @param jobs list of jobs per device
	 */
	private void countPendingDevicesPerDomain(List<DeviceArchive> jobs) {
		List<String> domains = this.domains;
		int[] counter = new int[domains.size()];
		for (DeviceArchive arch : jobs) {
			int index = domains.indexOf(arch.domain);
			if (0 <= index && index < counter.length) {
				counter[index]++;
			}
		}
		for (int index = 0; index < counter.length; ++index) {
			health.processingDevices(domains.get(index), counter[index]);
			if (counter[index] > 0) {
				LOGGER.info("{}: {} devices pending", domains.get(index), counter[index]);
			}
		}
		if (statistics != null) {
			statistics.dump();
		}
	}

	/**
	 * Process jobs per device.
	 * 
	 * @param jobs list of jobs
	 * @param index index within the list of jobs
	 */
	private void processJobs(final List<DeviceArchive> jobs, final int index) {
		if (busy.get()) {
			if (index < jobs.size()) {
				final DeviceArchive arch = jobs.get(index);
				arch.listArchives((res) -> {
					try {
						if (!arch.hasMore()) {
							health.processingDevices(arch.domain, -1);
						}
						processJobs(jobs, index + 1);
					} catch (RuntimeException ex) {
						ready();
					}
				});
			} else {
				Iterator<DeviceArchive> iterator = jobs.iterator();
				while (iterator.hasNext()) {
					DeviceArchive arch = iterator.next();
					if (!arch.hasMore()) {
						iterator.remove();
					}
				}
				if (!jobs.isEmpty()) {
					countPendingDevicesPerDomain(jobs);
					LOGGER.info("{} devices with pending data.", jobs.size());
					this.scheduler.schedule(new Runnable() {

						@Override
						public void run() {
							try {
								processJobs(jobs, 0);
							} catch (RuntimeException ex) {
								ready();
							}
						}
					}, processInitialDelayInSeconds, TimeUnit.SECONDS);

				} else {
					LOGGER.info("no more devices with pending data.");
					ready();
				}
			}
		}
	}

	/**
	 * Device archive state.
	 */
	private static class DeviceArchive {

		/**
		 * S3 processing health. May be {@code null}.
		 */
		private final S3ProcessorHealth health;
		/**
		 * S3 client to read the request data and write the archive files.
		 */
		private final S3ProxyClient s3Client;
		/**
		 * Domain name.
		 */
		private final String domain;
		/**
		 * S3 device key.
		 * <p>
		 * Already terminated with "/".
		 */
		private final String deviceKey;
		/**
		 * Buffer to copy and append S3 files.
		 */
		private final byte[] buffer = new byte[8192];
		/**
		 * Busy indication.
		 */
		private final AtomicReference<Consumer<Integer>> busy = new AtomicReference<>();
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
		 * Number of added days in this run.
		 */
		private volatile int addedDays;
		/**
		 * Indicates more days to process next time.
		 */
		private volatile boolean more;

		/**
		 * Create an device archive.
		 * 
		 * @param s3Client S3 client to read the request data and write the
		 *            archive files.
		 * @param health S3 processor health. May be {@code null}.
		 * @param domain domain name
		 * @param deviceKey S3 device key
		 * @throws NullPointerException if s3Client, domain or deviceKey is
		 *             {@code null}
		 */
		private DeviceArchive(S3ProxyClient s3Client, S3ProcessorHealth health, String domain, String deviceKey) {
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
			this.health = health;
			this.domain = domain;
			this.deviceKey = deviceKey;
		}

		/**
		 * Indicates, that there are more days to be appended in the next run.
		 * 
		 * @return {@code true}, if there are more days to append.
		 */
		private boolean hasMore() {
			return more;
		}

		/**
		 * Reports processing ready.
		 * 
		 * @param result processing result as http code. {@code -1} indicates a
		 *            generic failure.
		 * @return {@code true}, if this call ends processing, {@code false}, if
		 *         processing was already finished.
		 */
		private boolean ready(int result) {
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
		 * List archive file in order to append days.
		 * 
		 * @param ready consumer for result.
		 * @return {@code true}, if this call start processing, {@code false},
		 *         if processing was already started.
		 */
		private boolean listArchives(Consumer<Integer> ready) {
			if (busy.compareAndSet(null, ready)) {
				more = false;
				addedDays = -1;
				archDays = 0;
				archLastDate = null;
				if (archKey != null) {
					LOGGER.info("{} {}", domain, archKey);
					s3Client.load(S3Request.builder().key(archKey).cacheMode(CacheMode.NONE).build(),
							(response) -> listNextDays(response));
				} else {
					s3Client.list(S3ListRequest.builder().key(deviceKey + ARCH_RESOURCE_NAME).delimiter("/").build(),
							(t) -> {
								try {
									if (t != null) {
										List<S3Object> archs = t.getObjects();
										if (archs.isEmpty()) {
											archKey = null;
											listNextDays(null);
										} else {
											Collections.sort(archs);
											S3Object arch = archs.get(archs.size() - 1);
											archKey = arch.key;
											LOGGER.info("{} {} {}", domain, arch.key, arch.etag);
											s3Client.load(
													S3Request.builder().key(arch.key).cacheMode(CacheMode.NONE).build(),
													(response) -> listNextDays(response));
										}
									} else {
										ready(-1);
									}
								} catch (RuntimeException ex) {
									ready(-1);
								}
							});
				}
				return true;
			} else {
				return false;
			}
		}

		/**
		 * List next days to append to archive.
		 * 
		 * @param arch archive
		 */
		private void listNextDays(S3Response arch) {
			try {
				final ByteArrayOutputStream out = new ByteArrayOutputStream();
				String startAfter = null;
				int maxListDays = DAYS_PER_ARCH + 1;
				if (arch != null) {
					Map<String, String> metadata = arch.getMetadata();
					LocalDate lastDay = getLocalDate(metadata, METADATA_LASTDAY);
					Integer days = getInteger(metadata, METADATA_DAYS);
					if (lastDay != null && days != null) {
						LOGGER.info("{}: arch {} to {}, {} days", domain, archKey, lastDay, days);
						startAfter = deviceKey + lastDay.toString() + "/";
						if (days < DAYS_PER_ARCH) {
							try {
								append(arch.getContentAsStream(), out);
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
				s3Client.list(S3ListRequest.builder().key(deviceKey + "2").startAfter(startAfter).maxKeys(maxListDays)
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
		 * List messages of days.
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
					ready(200); // OK
					return;
				}

				Collections.sort(dates);

				boolean removeLast = true;
				String lastKey = dates.get(count - 1);
				String lastDate = getDateAsStringFromkey(lastKey);
				String thisDay = getCurrentDateAsString();

				if (lastDate != null) {
					if (lastDate.compareTo(thisDay) < 0) {
						LOGGER.info("{} {}, {} days, more available", domain, deviceKey, count);
						removeLast = (count + archDays) > DAYS_PER_ARCH;
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
					s3Client.list(S3ListRequest.builder().key(date).delimiter("/").build(), (messagesOfDay) -> {
						try {
							if (messagesOfDay != null) {
								newMessages.addAll(messagesOfDay.getObjects());
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
									String firstDate = getDateAsStringFromkey(firstKey);
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
		 * Load messages to append.
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
		 * Append new messages to archive.
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
					append(response.getContentAsStream(), out);
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

			String tail = "Z";
			Matcher matcher = INDEX.matcher(newArchKey);
			if (matcher.matches()) {
				tail = matcher.group(1);
			}
			newArchKey = StringUtil.truncateTail(newArchKey, tail);
			if (archDays < DAYS_PER_ARCH) {
				newArchKey += "+" + archDays;
			} else {
				newArchKey += "Z";
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
			builder.content(out.toByteArray());

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

		/**
		 * Append input stream to output stream.
		 * 
		 * @param in input stream with data to append
		 * @param out output stream to append data to
		 * @return number of bytes appended.
		 * @throws IOException if an i/o error occurred
		 */
		private int append(InputStream in, OutputStream out) throws IOException {
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

	}

	/**
	 * Get integer value from S3 metadata.
	 * 
	 * @param meta map with metadata
	 * @param name name of metadata
	 * @return integer value, or {@code null}, if not available or not a number.
	 */
	public static Integer getInteger(Map<String, String> meta, String name) {
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
	 * Get date value from S3 metadata.
	 * 
	 * @param meta map with metadata
	 * @param name name of metadata
	 * @return local date, or {@code null}, if not available or not a date.
	 */
	public static LocalDate getLocalDate(Map<String, String> meta, String name) {
		if (meta != null) {
			String value = meta.get(name);
			if (value != null) {
				return getLocalDate(name, value);
			}
		}
		return null;
	}

	/**
	 * Get local date from value.
	 * 
	 * @param name name of value (for logging)
	 * @param value value
	 * @return local date, or {@code null}, if value is not a date.
	 */
	public static LocalDate getLocalDate(String name, String value) {
		try {
			return LocalDate.parse(value);
		} catch (NumberFormatException ex) {
			LOGGER.info("{}={} is no date!", name, value);
		}
		return null;
	}

	/**
	 * Get date as string from S3 key.
	 * 
	 * @param key S3 key
	 * @return date as string, or {@code null}, if key doesn't match the date
	 *         pattern.
	 */
	public static String getDateAsStringFromkey(String key) {
		Matcher matcher = DATE.matcher(key);
		if (matcher.matches()) {
			return matcher.group(1);
		} else {
			LOGGER.info("{} is no date-key!", key);
			return null;
		}
	}

	/**
	 * Get the current date as string.
	 * 
	 * @return current date as string
	 */
	public static String getCurrentDateAsString() {
		LocalDate now = LocalDate.now(Clock.systemUTC());
		return now.toString();
	}
}
