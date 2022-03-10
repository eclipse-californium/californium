/*******************************************************************************
 * Copyright (c) 2022 Bosch.IO GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.extplugtests;

import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryMXBean;
import java.lang.management.MemoryUsage;
import java.lang.management.OperatingSystemMXBean;
import java.lang.management.ThreadMXBean;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;

/**
 * Several statistics based on {@link ManagementFactory}.
 * 
 * @since 3.4
 */
public class ManagementStatistic {

	/**
	 * Number representing {@code 1024*1024}.
	 */
	private static final long MEGA = 1024 * 1024L;

	/**
	 * LOgger to be used for logging.
	 */
	private final Logger logger;

	/**
	 * Indicates, that a GC is used, where a warning running out of heap
	 * indicates a shortage of memory. e.g. for ZGC that doesn't work so better
	 * don't print a warning for that.
	 */
	private final boolean warnMemoryUsage;

	/**
	 * Create a instance.
	 * 
	 * @param logger logger to be used for the statistic
	 */
	public ManagementStatistic(Logger logger) {
		this.logger = logger;
		ThreadMXBean mxBean = ManagementFactory.getThreadMXBean();
		if (mxBean.isThreadCpuTimeSupported() && !mxBean.isThreadCpuTimeEnabled()) {
			mxBean.setThreadCpuTimeEnabled(true);
		}
		Boolean zgc = null;
		List<String> gcNames = new ArrayList<>();
		for (GarbageCollectorMXBean gcMxBean : ManagementFactory.getGarbageCollectorMXBeans()) {
			String name = gcMxBean.getName();
			if (!gcNames.contains(name)) {
				gcNames.add(name);
				if (zgc == null || zgc) {
					zgc = name.startsWith("ZGC");
				}
			}
		}
		// ZGC will trigger warnings, so disable warnings
		warnMemoryUsage = zgc == null || !zgc;
		logger.info("GC: {}", gcNames);
	}

	/**
	 * Check, if a warning for memory usage should be used.
	 * 
	 * @return {@code true}, use memory warnings, {@code false}, if not.
	 */
	public boolean useWarningMemoryUsage() {
		return warnMemoryUsage;
	}

	/**
	 * Get accumulated GC collection counts.
	 * 
	 * @return accumulated GC collection counts
	 */
	public long getCollectionCount() {
		long gcCount = 0;
		for (GarbageCollectorMXBean gcMxBean : ManagementFactory.getGarbageCollectorMXBeans()) {
			long count = gcMxBean.getCollectionCount();
			if (0 < count) {
				gcCount += count;
			}
			logger.debug("{}: {} calls.", gcMxBean.getName(), count);
		}
		logger.debug("Overall {} calls.", gcCount);
		return gcCount;
	}

	/**
	 * Log management statistic.
	 */
	public void printManagementStatistic() {
		OperatingSystemMXBean osMxBean = ManagementFactory.getOperatingSystemMXBean();
		int processors = osMxBean.getAvailableProcessors();
		logger.info("{} processors", processors);
		ThreadMXBean threadMxBean = ManagementFactory.getThreadMXBean();
		if (threadMxBean.isThreadCpuTimeSupported() && threadMxBean.isThreadCpuTimeEnabled()) {
			long alltime = 0;
			long[] ids = threadMxBean.getAllThreadIds();
			for (long id : ids) {
				long time = threadMxBean.getThreadCpuTime(id);
				if (0 < time) {
					alltime += time;
				}
			}
			long pTime = alltime / processors;
			logger.info("cpu-time: {} ms (per-processor: {} ms)", TimeUnit.NANOSECONDS.toMillis(alltime),
					TimeUnit.NANOSECONDS.toMillis(pTime));
		}
		long gcCount = 0;
		long gcTime = 0;
		for (GarbageCollectorMXBean gcMxBean : ManagementFactory.getGarbageCollectorMXBeans()) {
			long count = gcMxBean.getCollectionCount();
			if (0 < count) {
				gcCount += count;
			}
			long time = gcMxBean.getCollectionTime();
			if (0 < time) {
				gcTime += time;
			}
			logger.info("{}: {} ms, {} calls.", gcMxBean.getName(), time, count);
		}
		logger.info("gc: {} ms, {} calls.", gcTime, gcCount);
		MemoryMXBean memoryMxBean = ManagementFactory.getMemoryMXBean();
		printMemoryUsage(logger, "heap", memoryMxBean.getHeapMemoryUsage());
		printMemoryUsage(logger, "non-heap", memoryMxBean.getNonHeapMemoryUsage());
		double loadAverage = osMxBean.getSystemLoadAverage();
		if (!(loadAverage < 0.0d)) {
			logger.info("average load: {}", String.format("%.2f", loadAverage));
		}
	}

	/**
	 * Log memory usage.
	 * 
	 * @param logger logger to write usage
	 * @param title title to be used for usage
	 * @param memoryUsage memory usage
	 */
	public static void printMemoryUsage(Logger logger, String title, MemoryUsage memoryUsage) {
		long max = memoryUsage.getMax();
		if (max > 0) {
			if (max > MEGA) {
				logger.info("{}: {} m-bytes used of {}/{}.", title, memoryUsage.getUsed() / MEGA,
						memoryUsage.getCommitted() / MEGA, max / MEGA);
			} else {
				logger.info("{}: {} bytes used of {}/{}.", title, memoryUsage.getUsed(), memoryUsage.getCommitted(),
						max);
			}
			return;
		}
		max = memoryUsage.getCommitted();
		if (max > MEGA) {
			logger.info("{}: {} m-bytes used of {}.", title, memoryUsage.getUsed() / MEGA, max / MEGA);
		} else {
			logger.info("{}: {} bytes used of {}.", title, memoryUsage.getUsed(), max);
		}
	}
}
