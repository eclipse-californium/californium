/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.javaspecialists.tjsn.concurrency.stripedexecutor.StripedExecutorService;

/**
 * Utility to create executors and optionally wrap them with a
 * {@link StripedExecutorService} for serialized execution, if required.
 * 
 * Though the usage of a {@link StripedExecutorService} comes with performance
 * drawback, this utility is intended to limit the usage of it. Therefore
 * unwrapped {@link ThreadPoolExecutor} are returned, which allows
 * {@link #stripes(ExecutorService)} to determine, how many threads are used for
 * immediate execution and use that number to eliminate not required
 * {@link StripedExecutorService}, if only one thread is used for that.
 * 
 * That differences from {@link java.util.concurrent.Executors}, which protects
 * some executors by wrapping the returned executor services, but also makes it
 * impossible to determine the number of used threads.
 * 
 * If californium uses {@link ScheduledExecutorService} for timers, the
 * callbacks are used to start on other job, potentially a striped job, if
 * serialized execution of jobs for a special resource is required (e.g.
 * Exchange). That enables a optimized usage of a special Executor, which uses
 * one thread for scheduled execution and others threads for immediately
 * execution. If only one other thread is used for immediately execution, no
 * {@link StripedExecutorService} is required also.
 * 
 * Note: THE INTERNAL/PRIVATE {@link SplitScheduledThreadPoolExecutor} IS
 * EXPERIMENTAL! IT'S INTENDED TO BE USED FOR REPRODUCING BENCHMARKS OF ISSUE
 * #690
 */
public class ExecutorsUtil {

	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(ExecutorsUtil.class.getCanonicalName());

	/**
	 * Thread group for timers.
	 */
	public static final ThreadGroup TIMER_THREAD_GROUP = new ThreadGroup("Timer"); //$NON-NLS-1$

	/**
	 * General scheduled executor intended for rare executing timers (e.g.
	 * cleanup task).
	 */
	private static final ScheduledThreadPoolExecutor scheduler;

	static {
		ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(2,
				new DaemonThreadFactory("Timer#", TIMER_THREAD_GROUP));
		scheduler = executor;
	}

	/**
	 * Threshold for using the experimental
	 * {@link SplitScheduledThreadPoolExecutor} to split thread pool into
	 * scheduled and immediately executing threads. Experimental! {@code 0} to
	 * disable the use of the {@link SplitScheduledThreadPoolExecutor}.
	 */
	private static final int SPLIT_THRESHOLD = 1;

	/**
	 * Create a scheduled thread pool executor service.
	 * 
	 * Experimentally, if the provided number of threads exceeds the
	 * {@link #SPLIT_THRESHOLD}, the {@link SplitScheduledThreadPoolExecutor} is
	 * returned.
	 * 
	 * @param poolSize number of threads for thread pool.
	 * @param threadFactory thread factory
	 * @return thread pool based scheduled executor service
	 */
	public static ScheduledExecutorService newScheduledThreadPool(int poolSize, ThreadFactory threadFactory) {
		if (SPLIT_THRESHOLD == 0 || poolSize <= SPLIT_THRESHOLD) {
			LOGGER.debug("create scheduled thread pool of {} threads", poolSize);
			ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(poolSize, threadFactory);
			return executor;
		} else {
			LOGGER.debug("create special thread pool of {} threads", poolSize);
			return new SplitScheduledThreadPoolExecutor(poolSize, threadFactory);
		}
	}

	/**
	 * Create a fixed thread pool.
	 * 
	 * @param poolSize number of threads for thread pool.
	 * @param threadFactory thread factory
	 * @return thread pool based executor service
	 */
	public static ExecutorService newFixedThreadPool(int poolSize, ThreadFactory threadFactory) {
		LOGGER.debug("create thread pool of {} threads", poolSize);
		return java.util.concurrent.Executors.newFixedThreadPool(poolSize, threadFactory);
	}

	/**
	 * Create a single threaded scheduled executor service.
	 * 
	 * @param threadFactory thread factory
	 * @return single threaded scheduled executor service
	 */
	public static ScheduledExecutorService newSingleThreadScheduledExecutor(ThreadFactory threadFactory) {
		LOGGER.debug("create scheduled single thread pool");
		ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1, threadFactory);
		executor.setMaximumPoolSize(1);
		return executor;
	}

	/**
	 * Get general scheduled executor.
	 * 
	 * Intended to be used for rare executing timers (e.g. cleanup tasks).
	 * 
	 * @return scheduled executor service
	 */
	public static ScheduledThreadPoolExecutor getScheduledExecutor() {
		return scheduler;
	}

	/**
	 * Ensure striped execution.
	 * 
	 * Use {@link StripedExecutorService} to execute jobs, if provided executor
	 * may execute jobs in parallel. If the provided executor service is created
	 * by this utility class, the number of threads in the pool used for
	 * execution are used to determine, if a {@link StripedExecutorService} is
	 * required.
	 * 
	 * @param executor executor to be used for striped execution.
	 * @return executor executing job in stripes.
	 */
	public static ExecutorService stripes(ExecutorService executor) {
		boolean required = true;
		if (executor instanceof StripedExecutorService) {
			required = false;
			LOGGER.debug("{} already striped!", executor.getClass().getName());
		}
		if (executor instanceof SplitScheduledThreadPoolExecutor) {
			required = ((SplitScheduledThreadPoolExecutor) executor).getExecutePoolSize() > 1;
			LOGGER.debug("special thread pool, stripe required {}", required);
		} else if (executor instanceof ThreadPoolExecutor) {
			required = ((ThreadPoolExecutor) executor).getMaximumPoolSize() > 1;
			LOGGER.debug("thread pool, stripe required {}", required);
		}
		if (required) {
			return new StripedExecutorService(executor);
		}
		return executor;
	}

	/**
	 * Experimental executor, which uses a {@link ScheduledThreadPoolExecutor}
	 * with {@link ExecutorsUtil#SPLIT_THRESHOLD} threads for scheduling, and an
	 * additional {@link ThreadPoolExecutor} for execution. This may result in
	 * better performance for direct job, when many scheduled job are queued for
	 * execution.
	 * 
	 * Note: IS EXPERIMENTAL! IT'S NOT INTENDED TO BE USED, EXCEPT FOR
	 * REPRODUCING BENCHMARKS OF ISSUE #690
	 */
	private static class SplitScheduledThreadPoolExecutor extends ScheduledThreadPoolExecutor {

		/**
		 * Direct thread pool executor for direct execution.
		 */
		private final ExecutorService directExecutor;
		/**
		 * Thread pool size of for job execution.
		 */
		private final int executePoolSize;

		/**
		 * Create new executor.
		 * 
		 * Split thread pool in {@link ScheduledThreadPoolExecutor} with
		 * {@link ExecutorsUtil#SPLIT_THRESHOLD} threads a
		 * {@link ThreadPoolExecutor} with the left number of threads of the
		 * provide pool size.
		 * 
		 * @param corePoolSize total number of threads used for this executor.
		 * @param threadFactory thread factory.
		 */
		public SplitScheduledThreadPoolExecutor(int corePoolSize, ThreadFactory threadFactory) {
			super(corePoolSize < SPLIT_THRESHOLD ? corePoolSize : SPLIT_THRESHOLD, threadFactory);
			if (corePoolSize > SPLIT_THRESHOLD) {
				executePoolSize = corePoolSize - SPLIT_THRESHOLD;
				directExecutor = newFixedThreadPool(executePoolSize, threadFactory);
			} else {
				executePoolSize = corePoolSize;
				directExecutor = null;
			}
		}

		/**
		 * Number of threads used for execution of threads.
		 * 
		 * @return number of threads used for execution of threads.
		 */
		public int getExecutePoolSize() {
			return executePoolSize;
		}

		@Override
		public void execute(Runnable command) {
			if (directExecutor == null) {
				super.execute(command);
			} else {
				directExecutor.execute(command);
			}
		}

		@Override
		public Future<?> submit(Runnable task) {
			if (directExecutor == null) {
				return super.submit(task);
			} else {
				return directExecutor.submit(task);
			}
		}

		@Override
		public <T> Future<T> submit(Runnable task, T result) {
			if (directExecutor == null) {
				return super.submit(task, result);
			} else {
				return directExecutor.submit(task, result);
			}
		}

		@Override
		public <T> Future<T> submit(Callable<T> task) {
			if (directExecutor == null) {
				return super.submit(task);
			} else {
				return directExecutor.submit(task);
			}
		}

		@Override
		public void shutdown() {
			if (directExecutor != null) {
				directExecutor.shutdown();
			}
			super.shutdown();
		}

		@Override
		public List<Runnable> shutdownNow() {
			List<Runnable> result = super.shutdownNow();
			if (directExecutor != null) {
				result.addAll(directExecutor.shutdownNow());
			}
			return result;
		}
	}
}
