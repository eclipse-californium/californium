/********************************************************************************
 * Copyright (c) 2023 Contributors to the Eclipse Foundation
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
package org.eclipse.californium.elements.util;

import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Monitors for system resource.
 * 
 * Check systems resource frequently for changes.
 * 
 * @since 3.8
 */
public class SystemResourceMonitors {

	/**
	 * Logger.
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(SystemResourceMonitors.class);

	/**
	 * List of system resource jobs.
	 */
	private final List<SystemResourceJob> resources = new ArrayList<>();
	/**
	 * Scheduler for jobs.
	 */
	private final ScheduledExecutorService scheduler;
	/**
	 * State indicator. {@code true} after {@link #start()}, {@code false} after
	 * {@link #stop()} or before {@link #start()}.
	 */
	private final AtomicBoolean running = new AtomicBoolean();

	/**
	 * Creates instance.
	 * 
	 * @param scheduler scheduler to schedule checking jobs.
	 */
	public SystemResourceMonitors(ScheduledExecutorService scheduler) {
		this.scheduler = scheduler;
	}

	/**
	 * Add system resource monitor.
	 * 
	 * @param name name of monitor
	 * @param interval interval for checks
	 * @param unit time unit for checks
	 * @param resource system resource monitor used for check.
	 * @return created check-job.
	 */
	public SystemResourceJob addMonitor(String name, long interval, TimeUnit unit, SystemResourceMonitor resource) {
		SystemResourceJob job = new SystemResourceJob(scheduler, name, interval, unit, resource);
		resources.add(job);
		if (running.get()) {
			job.start();
		}
		return job;
	}

	/**
	 * Remove system resource monitor job.
	 * 
	 * @param job system resource monitor check-job to remove
	 * @return {@code true}, if removed, {@code false}, if not contained.
	 */
	public boolean remove(SystemResourceJob job) {
		if (resources.remove(job)) {
			job.stop();
			return true;
		}
		return false;
	}

	/**
	 * Remove all system resource monitor check-jobs by name.
	 * 
	 * @param name name of check-jobs, or {@code null} for all check-jobs.
	 * @return {@code true}, if at least one check-job is removed,
	 *         {@code false}, if no check-job is removed.
	 */
	public boolean remove(String name) {
		boolean removed = false;
		Iterator<SystemResourceJob> iterator = resources.iterator();
		while (iterator.hasNext()) {
			SystemResourceJob job = iterator.next();
			if (name == null || name.equals(job.name)) {
				job.stop();
				iterator.remove();
				removed = true;
			}
		}
		return removed;
	}

	/**
	 * Start checks.
	 */
	public void start() {
		if (running.compareAndSet(false, true)) {
			for (SystemResourceJob job : resources) {
				job.start();
			}
			LOGGER.info("System resource monitor started!");
		}
	}

	/**
	 * Stop checks.
	 */
	public void stop() {
		if (running.compareAndSet(true, false)) {
			for (SystemResourceJob job : resources) {
				job.stop();
			}
			LOGGER.info("System resource monitor stopped!");
		}
	}

	/**
	 * Apply checks.
	 * 
	 * @param name name of check-jobs, or {@code null} for all check-jobs.
	 */
	public void checkNow(String name) {
		for (SystemResourceJob job : resources) {
			if (name == null || name.equals(job.name)) {
				job.checkNow();
			}
		}
		LOGGER.info("System resource monitor checked now!");
	}

	/**
	 * Interface to report result.
	 */
	public interface SystemResourceCheckReady {

		/**
		 * Report finished check-job.
		 * 
		 * @param stop {@code true}, stop check-job. {@code false}, schedule
		 *            next check.
		 */
		void ready(boolean stop);
	}

	/**
	 * Job to check system resource changes.
	 */
	public static class SystemResourceJob implements Runnable, SystemResourceCheckReady {

		/**
		 * Name of job.
		 */
		private final String name;
		/**
		 * Interval of check-job.
		 */
		private final long interval;
		/**
		 * Time unit of interval.
		 */
		private final TimeUnit unit;
		/**
		 * System resource monitor.
		 */
		private final SystemResourceMonitor resource;
		/**
		 * Scheduler for check-job interval.
		 */
		private final ScheduledExecutorService scheduler;
		/**
		 * Future of scheduled job.
		 */
		private final AtomicReference<ScheduledFuture<?>> scheduled = new AtomicReference<>();
		/**
		 * Indicates pending check.
		 */
		private final AtomicBoolean pending = new AtomicBoolean();

		/**
		 * Create check-job.
		 * 
		 * @param scheduler scheduler to be used.
		 * @param name name of job
		 * @param interval interval of checks
		 * @param unit unit of interval
		 * @param resource system resource monitor used for check.
		 */
		private SystemResourceJob(ScheduledExecutorService scheduler, String name, long interval, TimeUnit unit,
				SystemResourceMonitor resource) {
			this.scheduler = scheduler;
			this.name = name;
			this.interval = interval;
			this.unit = unit;
			this.resource = resource;
		}

		/**
		 * Stop check-job.
		 */
		private synchronized void stop() {
			ScheduledFuture<?> future = scheduled.getAndSet(null);
			if (future != null) {
				future.cancel(false);
			}
		}

		/**
		 * Start check-job.
		 */
		private synchronized void start() {
			ScheduledFuture<?> future = scheduled.getAndSet(scheduler.schedule(this, interval, unit));
			if (future != null) {
				future.cancel(false);
			}
			LOGGER.info("{} check scheduled in {} {}.", name, interval, unit);
		}

		/**
		 * Execute check-job now.
		 */
		private void checkNow() {
			if (pending.compareAndSet(false, true)) {
				ScheduledFuture<?> future = scheduled.get();
				if (future != null) {
					future.cancel(false);
				}
				resource.checkForUpdate(this);
			}
		}

		/**
		 * Execute scheduled check-job.
		 */
		private void check() {
			if (pending.compareAndSet(false, true)) {
				LOGGER.info("{} check for update!", name);
				resource.checkForUpdate(this);
			} else {
				LOGGER.info("{} check for update pending!", name);
			}
		}

		@Override
		public void run() {
			check();
		}

		@Override
		public void ready(boolean stop) {
			pending.set(false);
			LOGGER.info("{} check ready!", name);
			synchronized (this) {
				ScheduledFuture<?> future = scheduled.get();
				if (future != null) {
					if (stop) {
						future.cancel(false);
					} else {
						start();
					}
				}
			}
		}
	}

	/**
	 * System resource monitor.
	 */
	public interface SystemResourceMonitor {

		/**
		 * Check resource for update.
		 * 
		 * @param ready {@code true}
		 */
		void checkForUpdate(SystemResourceCheckReady ready);

	}

	/**
	 * File monitor.
	 * 
	 * Checks for changes in length and last modified date.
	 */
	public static abstract class FileMonitor implements SystemResourceMonitor {

		/**
		 * Monitored values.
		 */
		public static class MonitoredValues {

			private final long lastModified;
			private final long length;

			private MonitoredValues(long lastModified, long length) {
				this.lastModified = lastModified;
				this.length = length;
			}

			/**
			 * Check monitored values.
			 * 
			 * @param other other monitored values
			 * @return {@code true}, if other monitored values differ,
			 *         {@code false}, if other monitored values are equal.
			 */
			private boolean check(MonitoredValues other) {
				return lastModified != other.lastModified || length != other.length;
			}
		}

		/**
		 * File to monitor.
		 */
		private final File file;
		/**
		 * Last monitored values when reading the file.
		 */
		private volatile MonitoredValues values;

		/**
		 * Create file monitor.
		 * 
		 * @param name name of file to monitor
		 */
		public FileMonitor(String name) {
			this(new File(name));
		}

		/**
		 * Create file monitor.
		 * 
		 * @param file file to monitor
		 */
		public FileMonitor(File file) {
			this.file = file;
			this.values = readMonitoredValues();
		}

		/**
		 * Read monitored values.
		 * 
		 * @return monitored values.
		 */
		private MonitoredValues readMonitoredValues() {
			long length = file.length();
			long lastModified = file.lastModified();
			return new MonitoredValues(lastModified, length);
		}

		@Override
		public void checkForUpdate(SystemResourceCheckReady ready) {
			MonitoredValues values = readMonitoredValues();
			if (this.values.check(values)) {
				LOGGER.info("File {} changed!", file);
				update(values, ready);
			} else {
				LOGGER.info("File {} unchanged.", file);
				ready.ready(false);
			}
		}

		/**
		 * Report update ready.
		 * 
		 * @param values monitored values passed to {@link #update}.
		 *            {@code null}, if monitored values should not be updated.
		 */
		protected void ready(MonitoredValues values) {
			if (values != null) {
				this.values = values;
			}
		}

		/**
		 * Called, when monitored values differs.
		 * 
		 * @param values different monitored values
		 * @param ready callback to report finished update
		 */
		protected abstract void update(MonitoredValues values, SystemResourceCheckReady ready);
	}

}
