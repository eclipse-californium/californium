/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility to create executors.
 * 
 * According some web sources, using {@link ScheduledFuture#cancel(boolean)} may
 * cause resource leaks, because the {@link Runnable} is removed delayed.
 * Especially "long term" scheduled tasks, which are frequently scheduled and
 * canceled may be affected of that. To mitigate that, since java 7 the
 * {@link ScheduledThreadPoolExecutor#setRemoveOnCancelPolicy(boolean)} can be
 * used. The {@link ScheduledThreadPoolExecutor} will be configured using the
 * value of environment-variable or java-property
 * {@code "EXECUTER_REMOVE_ON_CANCEL"} or {@link #DEFAULT_REMOVE_ON_CANCEL}.
 * 
 * Test with java 11 didn't show such leaks, even if the task are removed
 * delayed, they are removed much earlier than their scheduled time.
 * 
 * Note: THE INTERNAL/PRIVATE {@code SplitScheduledThreadPoolExecutor} IS A
 * WORKAROUND! IT MAY BE REPLACED IN THE FUTURE. See issue #690.
 */
public class ExecutorsUtil {

	/** the logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(ExecutorsUtil.class);

	private static final Runnable WARMUP = new Runnable() {

		@Override
		public void run() {
			LOGGER.trace("warmup ...");
		}
	};

	/**
	 * Thread group for timers.
	 */
	public static final ThreadGroup TIMER_THREAD_GROUP = new ThreadGroup("Timer"); //$NON-NLS-1$

	/**
	 * Threshold for using the {@link SplitScheduledThreadPoolExecutor} to split
	 * thread pool into scheduled and immediately executing threads. {@code 0}
	 * to disable the use of the {@link SplitScheduledThreadPoolExecutor}.
	 */
	private static final int SPLIT_THRESHOLD = 1;

	/**
	 * Default value for {@link #REMOVE_ON_CANCEL}, if
	 * {@code "EXECUTER_REMOVE_ON_CANCEL"} is not available.
	 * 
	 * @since 3.0
	 */
	private static final Boolean DEFAULT_REMOVE_ON_CANCEL = true;
	/**
	 * General "remove on cancel" policy. Only applies for java 7 or newer.
	 * 
	 * Set by the value of environment-variable or java-property
	 * {@code "EXECUTER_REMOVE_ON_CANCEL"} or {@link #DEFAULT_REMOVE_ON_CANCEL}.
	 * 
	 * @see StringUtil#getConfigurationBoolean(String)
	 * @since 3.0
	 */
	private static final Boolean REMOVE_ON_CANCEL;

	static {
		Boolean remove = StringUtil.getConfigurationBoolean("EXECUTER_REMOVE_ON_CANCEL");
		if (remove == null) {
			remove = DEFAULT_REMOVE_ON_CANCEL;
		}
		if (remove != null) {
			try {
				ScheduledThreadPoolExecutor.class.getMethod("setRemoveOnCancelPolicy", Boolean.TYPE);
			} catch (NoSuchMethodException e) {
				remove = null;
			}
		}
		REMOVE_ON_CANCEL = remove;
	}

	/**
	 * Create a scheduled thread pool executor service.
	 * 
	 * If the provided number of threads exceeds the {@link #SPLIT_THRESHOLD},
	 * the {@code SplitScheduledThreadPoolExecutor} is returned.
	 * 
	 * @param poolSize number of threads for thread pool.
	 * @param threadFactory thread factory
	 * @return thread pool based scheduled executor service
	 */
	public static ScheduledExecutorService newScheduledThreadPool(int poolSize, ThreadFactory threadFactory) {
		if (SPLIT_THRESHOLD == 0 || poolSize <= SPLIT_THRESHOLD) {
			LOGGER.trace("create scheduled thread pool of {} threads", poolSize);
			ScheduledExecutorService executor = Executors.newScheduledThreadPool(poolSize, threadFactory);
			setRemoveOnCancelPolicy(executor);
			executor.execute(WARMUP);
			return executor;
		} else {
			LOGGER.trace("create special thread pool of {} threads", poolSize);
			SplitScheduledThreadPoolExecutor executor = new SplitScheduledThreadPoolExecutor(poolSize, threadFactory);
			executor.execute(WARMUP);
			executor.schedule(WARMUP, 0, TimeUnit.NANOSECONDS);
			return executor;
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
		LOGGER.trace("create thread pool of {} threads", poolSize);
		ExecutorService executor = Executors.newFixedThreadPool(poolSize, threadFactory);
		executor.execute(WARMUP);
		return executor;
	}

	/**
	 * Create a single threaded scheduled executor service.
	 * 
	 * @param threadFactory thread factory
	 * @return single threaded scheduled executor service
	 */
	public static ScheduledExecutorService newSingleThreadScheduledExecutor(ThreadFactory threadFactory) {
		LOGGER.trace("create scheduled single thread pool");
		ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(threadFactory);
		setRemoveOnCancelPolicy(executor);
		executor.execute(WARMUP);
		return executor;
	}

	/**
	 * Create a scheduler with 2 threads in pools.
	 * 
	 * Intended to be used for rare executing timers (e.g. cleanup tasks).
	 * 
	 * @param namePrefix for thread names.
	 * @return scheduled executor service
	 */
	public static ScheduledThreadPoolExecutor newDefaultSecondaryScheduler(String namePrefix) {
		ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(2, new NamedThreadFactory(namePrefix));
		setRemoveOnCancelPolicy(executor);
		executor.execute(WARMUP);
		executor.prestartAllCoreThreads();
		return executor;
	}

	/**
	 * Shutdown executor gracefully by waiting for task terminations.
	 * 
	 * @param timeMaxToWaitInMs max time to wait in milliseconds for task
	 *            completions, after this time a more aggressive
	 *            {@link ExecutorService#shutdownNow()} will be called.
	 * @param executors executors to shutdown
	 */
	public static void shutdownExecutorGracefully(long timeMaxToWaitInMs, ExecutorService... executors) {
		if (executors.length == 0) {
			return;
		}

		long start = ClockUtil.nanoRealtime();

		// shutdown executor
		for (ExecutorService executor : executors) {
			executor.shutdown();
		}

		long time = TimeUnit.NANOSECONDS.toMillis(ClockUtil.nanoRealtime() - start);
		if (time > timeMaxToWaitInMs) {
			LOGGER.warn("shutdown {} ms exceeded the maximum {} ms", time, timeMaxToWaitInMs);
		}

		// wait for task termination
		try {
			long timeToWait = (timeMaxToWaitInMs / executors.length) / 2;
			for (ExecutorService executor : executors) {
				if (!executor.awaitTermination(timeToWait, TimeUnit.MILLISECONDS)) {
					// cancel still executing tasks
					// and ignore all remaining tasks scheduled for later
					List<Runnable> runningTasks = executor.shutdownNow();
					if (runningTasks.size() > 0) {
						// this is e.g. the case if we have performed an
						// incomplete blockwise transfer
						// and the BlockwiseLayer has scheduled a
						// pending BlockCleanupTask for tidying up
						LOGGER.debug("ignoring remaining {} scheduled task(s)", runningTasks.size());
					}
					// wait for executing tasks to respond to being cancelled
					executor.awaitTermination(timeToWait, TimeUnit.MILLISECONDS);
				}
			}
		} catch (InterruptedException e) {
			for (ExecutorService executor : executors) {
				executor.shutdownNow();
			}
			Thread.currentThread().interrupt();
		} finally {
			time = TimeUnit.NANOSECONDS.toMillis(ClockUtil.nanoRealtime() - start);
			if (time > timeMaxToWaitInMs) {
				LOGGER.warn("await termination {} ms exceeded the maximum {} ms", time, timeMaxToWaitInMs);
			}
		}
	}

	/**
	 * Set remove on cancel policy of provided executor.
	 * 
	 * Ignored, if not supported by java vm or executors implementation.
	 * 
	 * @param executor executor to set remove on cancel policy
	 * @since 3.0
	 */
	@NotForAndroid
	private static void setRemoveOnCancelPolicy(ScheduledExecutorService executor) {
		if (REMOVE_ON_CANCEL != null && executor instanceof ScheduledThreadPoolExecutor) {
			((ScheduledThreadPoolExecutor) executor).setRemoveOnCancelPolicy(REMOVE_ON_CANCEL);
		}
	}

	/**
	 * Executor, which uses a {@link ScheduledThreadPoolExecutor} with
	 * {@link ExecutorsUtil#SPLIT_THRESHOLD} threads for scheduling, and an
	 * additional {@link ThreadPoolExecutor} for execution. This may result in
	 * better performance for direct job, when many scheduled job are queued for
	 * execution.
	 * 
	 * Note: IT'S A WORKAROUND! IT MAY BE REPLACED IN THE FUTURE! See issue
	 * #690.
	 */
	private static class SplitScheduledThreadPoolExecutor extends ScheduledThreadPoolExecutor {

		private final long SCHEDULE_EXECUTOR_LOGGING_QUEUE_SIZE_DIFF_DEFAULT = 10000;
		/**
		 * Direct thread pool executor for direct execution.
		 */
		private final ExecutorService directExecutor;
		/**
		 * Last schedule queue size.
		 */
		private AtomicLong scheduleQueueSize = new AtomicLong();

		private final long scheduleLoggingQueueSizeDiff;

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
			setMaximumPoolSize(corePoolSize < SPLIT_THRESHOLD ? corePoolSize : SPLIT_THRESHOLD);
			Long diff = StringUtil.getConfigurationLong("EXECUTER_LOGGING_QUEUE_SIZE_DIFF");
			scheduleLoggingQueueSizeDiff = diff == null ? SCHEDULE_EXECUTOR_LOGGING_QUEUE_SIZE_DIFF_DEFAULT : diff;
			ExecutorsUtil.setRemoveOnCancelPolicy(this);
			if (corePoolSize > SPLIT_THRESHOLD) {
				directExecutor = newFixedThreadPool(corePoolSize - SPLIT_THRESHOLD, threadFactory);
			} else {
				directExecutor = null;
			}
			LOGGER.debug("remove on cancel: {}, split: {}, log-diff: {}", REMOVE_ON_CANCEL, directExecutor != null,
					scheduleLoggingQueueSizeDiff);
		}

		@Override
		public void execute(Runnable command) {
			if (directExecutor == null) {
				super.execute(command);
			} else {
				long lastSize = scheduleQueueSize.get();
				long size = getQueue().size();
				long diff = Math.abs(lastSize - size);
				if (diff > scheduleLoggingQueueSizeDiff && scheduleQueueSize.compareAndSet(lastSize, size)) {
					LOGGER.debug("Job queue {}", size);
					purge();
				}
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

		@Override
		public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
			if (directExecutor != null) {
				if (!directExecutor.awaitTermination(timeout / 2, unit)) {
					return false;
				}
				return super.awaitTermination(timeout / 2, unit);
			} else {
				return super.awaitTermination(timeout, unit);
			}
		}
	}
}
