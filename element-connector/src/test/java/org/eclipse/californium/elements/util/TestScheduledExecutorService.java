/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch.IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.Delayed;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * ScheduledExecutorService for unit tests.
 * 
 * Jobs are executed by calling {@link #executeJobs()}, not by time schedule.
 * 
 * @since 2.4
 */
public class TestScheduledExecutorService implements ScheduledExecutorService {

	/**
	 * List of pending jobs.
	 */
	private final List<Runnable> jobs = new ArrayList<Runnable>();
	/**
	 * Shutdown indicator.
	 */
	private volatile boolean shutdown;
	/**
	 * Termination indicator.
	 */
	private volatile boolean terminated;

	/**
	 * Create test scheduler.
	 */
	public TestScheduledExecutorService() {
	}

	@Override
	public void shutdown() {
		shutdown = true;
	}

	@Override
	public List<Runnable> shutdownNow() {
		this.shutdown = true;
		synchronized (this.jobs) {
			List<Runnable> jobs = new ArrayList<Runnable>(this.jobs);
			this.jobs.clear();
			this.terminated = true;
			this.jobs.notifyAll();
			return jobs;
		}
	}

	@Override
	public boolean isShutdown() {
		return shutdown;
	}

	@Override
	public boolean isTerminated() {
		return terminated;
	}

	@Override
	public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
		synchronized (this.jobs) {
			if (!terminated) {
				this.jobs.wait(unit.toMillis(timeout));
			}
		}
		return terminated;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Not implemented.
	 * 
	 * @throws RuntimeException "not supported!"
	 */
	@Override
	public <T> Future<T> submit(Callable<T> task) {
		throw new RuntimeException("not supported!");
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Not implemented.
	 * 
	 * @throws RuntimeException "not supported!"
	 */
	@Override
	public <T> Future<T> submit(Runnable task, T result) {
		throw new RuntimeException("not supported!");
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Not implemented.
	 * 
	 * @throws RuntimeException "not supported!"
	 */
	@Override
	public Future<?> submit(Runnable task) {
		throw new RuntimeException("not supported!");
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Not implemented.
	 * 
	 * @throws RuntimeException "not supported!"
	 */
	@Override
	public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks) throws InterruptedException {
		throw new RuntimeException("not supported!");
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Not implemented.
	 * 
	 * @throws RuntimeException "not supported!"
	 */
	@Override
	public <T> List<Future<T>> invokeAll(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit)
			throws InterruptedException {
		throw new RuntimeException("not supported!");
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Not implemented.
	 * 
	 * @throws RuntimeException "not supported!"
	 */
	@Override
	public <T> T invokeAny(Collection<? extends Callable<T>> tasks) throws InterruptedException, ExecutionException {
		throw new RuntimeException("not supported!");
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Not implemented.
	 * 
	 * @throws RuntimeException "not supported!"
	 */
	@Override
	public <T> T invokeAny(Collection<? extends Callable<T>> tasks, long timeout, TimeUnit unit)
			throws InterruptedException, ExecutionException, TimeoutException {
		throw new RuntimeException("not supported!");
	}

	@Override
	public void execute(Runnable command) {
		if (shutdown) {
			throw new RejectedExecutionException("already shutdown!");
		}
		jobs.add(command);
	}

	@Override
	public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
		if (shutdown) {
			throw new RejectedExecutionException("already shutdown!");
		}
		ScheduledRunnable job = new ScheduledRunnable(command, delay, unit);
		jobs.add(job);
		return job;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Not implemented.
	 * 
	 * @throws RuntimeException "not supported!"
	 */
	@Override
	public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) {
		throw new RuntimeException("not supported!");
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Not implemented.
	 * 
	 * @throws RuntimeException "not supported!"
	 */
	@Override
	public ScheduledFuture<?> scheduleAtFixedRate(Runnable command, long initialDelay, long period, TimeUnit unit) {
		throw new RuntimeException("not supported!");
	}

	/**
	 * {@inheritDoc}
	 * 
	 * Not implemented.
	 * 
	 * @throws RuntimeException "not supported!"
	 */
	@Override
	public ScheduledFuture<?> scheduleWithFixedDelay(Runnable command, long initialDelay, long delay, TimeUnit unit) {
		throw new RuntimeException("not supported!");
	}

	/**
	 * Cancel all pending jobs.
	 */
	public void cancelAll() {
		synchronized (jobs) {
			jobs.clear();
		}
	}

	/**
	 * Execute all currently pending jobs.
	 * 
	 * @return number of executed jobs.
	 */
	public int executeJobs() {
		int count = 0;
		List<Runnable> currentJobs;
		synchronized (jobs) {
			currentJobs = new ArrayList<Runnable>(jobs);
		}
		for (Runnable run : currentJobs) {
			if (!shutdown && isPending(run)) {
				run.run();
				++count;
			}
		}
		synchronized (jobs) {
			if (shutdown && jobs.isEmpty()) {
				terminated = true;
				jobs.notify();
			}
		}
		return count;
	}

	/**
	 * Test, if job is pending.
	 * 
	 * @param run job to test.
	 * @return {@code true}, if job is pending, {@code false}, if job was
	 *         canceled in the meantime.
	 */
	private boolean isPending(Runnable run) {
		synchronized (jobs) {
			if (jobs.remove(run)) {
				if (run instanceof ScheduledFuture) {
					@SuppressWarnings("unchecked")
					ScheduledFuture<Void> future = (ScheduledFuture<Void>) run;
					return !future.isCancelled();
				}
			}
			return false;
		}
	}

	/**
	 * Implementation of {@link ScheduledFuture}.
	 */
	private class ScheduledRunnable implements Runnable, ScheduledFuture<Void> {

		private final Runnable job;
		private final long delay;
		private final TimeUnit unit;
		private volatile boolean completed;
		private volatile boolean cancelled;

		private ScheduledRunnable(Runnable job, long delay, TimeUnit unit) {
			this.job = job;
			this.delay = delay;
			this.unit = unit;
		}

		@Override
		public long getDelay(TimeUnit unit) {
			return unit.convert(delay, this.unit);
		}

		@Override
		public int compareTo(Delayed o) {
			return (int) (getDelay(TimeUnit.NANOSECONDS) - o.getDelay(TimeUnit.NANOSECONDS));
		}

		@Override
		public boolean cancel(boolean mayInterruptIfRunning) {
			if (!completed && !cancelled) {
				cancelled = true;
				synchronized (jobs) {
					jobs.remove(this);
				}
				if (mayInterruptIfRunning) {
					Thread.currentThread().interrupt();
				}
			}
			return cancelled;
		}

		@Override
		public boolean isCancelled() {
			return cancelled;
		}

		@Override
		public boolean isDone() {
			return completed;
		}

		@Override
		public Void get() throws InterruptedException, ExecutionException {
			return null;
		}

		@Override
		public Void get(long timeout, TimeUnit unit) throws InterruptedException, ExecutionException, TimeoutException {
			return null;
		}

		@Override
		public void run() {
			if (!cancelled) {
				this.job.run();
				if (!cancelled) {
					completed = true;
				}
			}
		}

	}
}
