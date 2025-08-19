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

import java.time.Clock;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

import org.eclipse.californium.cloud.BaseServer;
import org.eclipse.californium.cloud.s3.S3ProxyServer;
import org.eclipse.californium.cloud.s3.S3ProxyServer.S3ProxyConfig.S3ProcessorConfig;
import org.eclipse.californium.cloud.s3.proxy.S3ListRequest;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClientProvider;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.CounterStatisticManager;
import org.eclipse.californium.elements.util.LeastRecentlyUpdatedCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * S3 processor.
 * <p>
 * Schedules {@link S3BaseJob}s execution.
 * 
 * @since 3.13
 */
public class S3Processor {

	private static final Logger LOGGER = LoggerFactory.getLogger(S3Processor.class);

	/**
	 * S3-key prefix to list devices.
	 */
	public static final String RESOURCE_NAME = "devices/";

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
	private final ConcurrentHashMap<String, LeastRecentlyUpdatedCache<String, S3BaseJob>> domainJobs;
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
	 * Minutes to grant keeping the device jobs in volatile memory.
	 */
	private final long minutes;
	/**
	 * Maximum number of device jobs to keep in volatile memory.
	 */
	private final int maxDevices;
	/**
	 * Minimum number of device jobs to keep in volatile memory.
	 */
	private final int minDevices;
	/**
	 * S3 processor up to date.
	 * 
	 * @since 4.0
	 */
	private final String uptoDate;
	/**
	 * S3 processor number of days not to process.
	 * 
	 * @since 4.0
	 */
	private final Integer uptoDay;
	/**
	 * S3 processor domains.
	 * 
	 * @since 4.0
	 */
	private final List<String> domains;
	/**
	 * S3 processor devices.
	 * 
	 * @since 4.0
	 */
	private final List<String> devices;
	/**
	 * Factory to create job for device.
	 * 
	 * @since 4.0
	 */
	private final S3JobFactory factory;

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
	 * Create S3 processor.
	 * 
	 * @param s3ProcessorConfig cli configuration. May be {@code null}.
	 * @param config configuration
	 * @param s3Clients S3 clients provider to read the request data and write
	 *            the archive files.
	 * @param health S3 processor health. May be {@code null}.
	 * @param scheduler scheduler for S3 jobs.
	 * @throws NullPointerException if config, s3Clients, or scheduler is
	 *             {@code null}
	 * @since 4.0 (added s3ProcessorConfig)
	 */
	public S3Processor(S3ProcessorConfig s3ProcessorConfig, Configuration config, S3ProxyClientProvider s3Clients,
			S3ProcessorHealth health, ScheduledExecutorService scheduler) {
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
		this.domainJobs = new ConcurrentHashMap<>();

		this.minutes = config.get(BaseServer.CACHE_STALE_DEVICE_THRESHOLD, TimeUnit.MINUTES);
		this.maxDevices = config.get(BaseServer.CACHE_MAX_DEVICES);
		int minDevices = this.maxDevices / 10;
		if (minDevices < 100) {
			minDevices = this.maxDevices;
		}
		this.minDevices = minDevices;
		String function = "arch";
		String uptoDate = null;
		Integer uptoDay = null;
		List<String> domains = null;
		List<String> devices = null;
		boolean test = false;
		if (s3ProcessorConfig != null) {
			function = s3ProcessorConfig.function;
			domains = s3ProcessorConfig.domains;
			devices = s3ProcessorConfig.devices;
			uptoDate = s3ProcessorConfig.upTo;
			test = s3ProcessorConfig.test;
			if (uptoDate != null) {
				try {
					LocalDate.parse(uptoDate);
				} catch (DateTimeParseException ex) {
					try {
						uptoDay = Integer.parseInt(uptoDate);
						if (uptoDay < 0) {
							uptoDate = getCurrentDateAsString(uptoDay);
							uptoDay = null;
						} else {
							uptoDate = null;
						}
					} catch (NumberFormatException e) {
						LOGGER.info("invalid upto '{}'!", uptoDate);
						function = null;
					}
				}
			}
		}
		this.uptoDate = uptoDate;
		this.uptoDay = uptoDay;
		this.domains = domains;
		this.devices = devices;
		S3JobFactory factory = null;
		if (function != null) {
			if (processDailyTimeInSeconds > 0) {
				LOGGER.info("S3 processor: schedule daily at {}s{}.", processDailyTimeInSeconds,
						test ? " (test only)" : "");
			} else if (processIntervalInSeconds > 0) {
				LOGGER.info("S3 processor: schedule interval {}s{}.", processIntervalInSeconds,
						test ? " (test only)" : "");
			} else {
				LOGGER.info("S3 processor: no schedule.");
				function = null;
			}
		}
		if (function != null) {
			if (uptoDate != null) {
				LOGGER.info("S3 processor: {} upto {}", function, uptoDate);
			} else if (uptoDay != null) {
				LOGGER.info("S3 processor: {} upto {} left days", function, uptoDay);
			}
			final boolean testOnly = test;
			if (function.equals("arch")) {
				factory = (s3Client, domain, deviceKey) -> {
					return new S3ArchJob(s3Client, domain, deviceKey, testOnly, health);
				};
			} else if (function.equals("deldays")) {
				factory = (s3Client, domain, deviceKey) -> {
					return new S3DeleteDaysJob(s3Client, domain, deviceKey, testOnly, health);
				};
			} else if (function.equals("delseries")) {
				factory = (s3Client, domain, deviceKey) -> {
					return new S3DeleteSeriesJob(s3Client, domain, deviceKey, testOnly, health);
				};
			} else if (function.equals("compress")) {
				factory = (s3Client, domain, deviceKey) -> {
					return new S3CompressJob(s3Client, domain, deviceKey, testOnly, health);
				};
			} else if (function.equals("append")) {
				factory = (s3Client, domain, deviceKey) -> {
					return new S3AppendJob(s3Client, domain, deviceKey, testOnly, health);
				};
			} else if (function.equals("restore")) {
				factory = (s3Client, domain, deviceKey) -> {
					return new S3RestoreJob(s3Client, domain, deviceKey, testOnly, health);
				};
			} else {
				LOGGER.warn("Function {} unknown.", function);
			}
		}
		this.factory = factory;
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
		for (LeastRecentlyUpdatedCache<String, S3BaseJob> domain : domainJobs.values()) {
			domain.clear();
		}
		domainJobs.clear();
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
		boolean res = factory != null && busy.compareAndSet(false, true);
		if (res) {
			try {
				if (statistics != null) {
					statistics.transferCounter();
				}
				LOGGER.info("Start ...");
				List<S3BaseJob> jobs = new ArrayList<>();
				List<String> domains = new ArrayList<>(s3Clients.getDomains());
				listDevicesPerDomain(domains, 0, jobs);
			} catch (RuntimeException ex) {
				LOGGER.warn("Process first job failed!", ex);
				ready();
			}
		}
		return res;
	}

	/**
	 * Filter domains.
	 * 
	 * @param domain domain name to filter
	 * @return {@code true} to include domain in processing, {@code false} to
	 *         exclude domain from processing.
	 * @see #domains
	 * @since 4.0
	 */
	private boolean filterDomain(String domain) {
		if (domains == null || domains.isEmpty()) {
			return true;
		}
		return domains.contains(domain);
	}

	/**
	 * Filter devices.
	 * 
	 * @param device device name to filter
	 * @return {@code true} to include device in processing, {@code false} to
	 *         exclude device from processing.
	 * @see #devices
	 * @since 4.0
	 */
	private boolean filterDevice(String device) {
		if (devices == null || devices.isEmpty()) {
			return true;
		}
		for (String name : devices) {
			if (device.contains(name)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * List device of a domain.
	 * 
	 * @param domains list of domains.
	 * @param index index of domain in domains.
	 * @param jobs list of jobs to add the jobs for each device.
	 * @since 4.0 (added domains)
	 */
	private void listDevicesPerDomain(final List<String> domains, int index, final List<S3BaseJob> jobs) {
		if (busy.get()) {
			while (index < domains.size()) {
				String domain = domains.get(index);
				if (filterDomain(domain)) {
					break;
				}
				LOGGER.info("skip domain {}", domain);
				++index;
			}
			if (index < domains.size()) {
				final String domain = domains.get(index);
				LOGGER.info("list domain {}", domain);
				LeastRecentlyUpdatedCache<String, S3BaseJob> cache = domainJobs.get(domain);
				if (cache == null) {
					cache = new LeastRecentlyUpdatedCache<>(minDevices, maxDevices, minutes, TimeUnit.MINUTES);
					domainJobs.put(domain, cache);
				}
				final LeastRecentlyUpdatedCache<String, S3BaseJob> domainCache = cache;
				final S3ProxyClient s3Client = s3Clients.getProxyClient(domain);
				final int nextIndex = index + 1;
				s3Client.list(S3ListRequest.builder().prefix(RESOURCE_NAME).delimiter("/").build(), (t) -> {
					try {
						if (t != null) {
							List<String> devices = t.getPrefixes();
							int count = 0;
							for (String device : devices) {
								if (filterDevice(device)) {
									++count;
									S3BaseJob arch = domainCache.get(device);
									if (arch == null) {
										arch = factory.create(s3Client, domain, device);
										domainCache.put(device, arch);
									}
									jobs.add(arch);
								}
							}
							if (count > 0) {
								LOGGER.info("{}: jobs for {} of {} devices", domain, count, devices.size());
							} else {
								LOGGER.info("{}: no match in {} devices", domain, devices.size());
							}
						}
						listDevicesPerDomain(domains, nextIndex, jobs);
					} catch (RuntimeException ex) {
						LOGGER.warn("list domain {} failed!", domain, ex);
						ready();
					}
				});
			} else {
				countPendingDevicesPerDomain(domains, jobs);
				processJobs(domains, jobs, 0);
			}
		}
	}

	/**
	 * Reports a statistic of pending device per domain.
	 * 
	 * @param domains list of domains.
	 * @param jobs list of jobs per device
	 * @since 4.0 (added domains)
	 */
	private void countPendingDevicesPerDomain(List<String> domains, List<S3BaseJob> jobs) {
		int[] counter = new int[domains.size()];
		for (S3BaseJob arch : jobs) {
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
	 * @param domains list of domains.
	 * @param jobs list of jobs
	 * @param index index within the list of jobs
	 * @since 4.0 (added domains)
	 */
	private void processJobs(final List<String> domains, final List<S3BaseJob> jobs, final int index) {
		if (busy.get()) {
			if (index < jobs.size()) {
				final S3BaseJob arch = jobs.get(index);
				Consumer<Integer> ready = (res) -> {
					try {
						if (!arch.hasMore()) {
							health.processingDevices(arch.domain, -1);
						}
						processJobs(domains, jobs, index + 1);
					} catch (RuntimeException ex) {
						LOGGER.warn("Process {}. job failed!", index, ex);
						ready();
					}
				};
				arch.start(uptoDate, uptoDay, ready);
			} else {
				Iterator<S3BaseJob> iterator = jobs.iterator();
				while (iterator.hasNext()) {
					S3BaseJob arch = iterator.next();
					if (!arch.hasMore()) {
						iterator.remove();
					}
				}
				if (!jobs.isEmpty()) {
					countPendingDevicesPerDomain(domains, jobs);
					LOGGER.info("{} devices with pending data.", jobs.size());
					this.scheduler.schedule(new Runnable() {

						@Override
						public void run() {
							try {
								processJobs(domains, jobs, 0);
							} catch (RuntimeException ex) {
								LOGGER.warn("Process first job failed!", index, ex);
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
	 * Factory to create jobs.
	 * 
	 * @since 4.0
	 */
	private static interface S3JobFactory {

		/**
		 * Create device job.
		 * 
		 * @param s3Client s3client to use
		 * @param domain domain
		 * @param deviceKey device key
		 * @return device job
		 */
		S3BaseJob create(S3ProxyClient s3Client, String domain, String deviceKey);
	}

	/**
	 * Gets the current date as string.
	 * 
	 * @param daysOffset days offset
	 * @return current date as string
	 * @since 4.0
	 */
	public static String getCurrentDateAsString(int daysOffset) {
		LocalDate now = LocalDate.now(Clock.systemUTC());
		return now.plusDays(daysOffset).toString();
	}

}
