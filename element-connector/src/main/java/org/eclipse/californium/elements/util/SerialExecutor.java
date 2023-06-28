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

import java.util.ArrayList;
import java.util.Collection;
import java.util.ConcurrentModificationException;
import java.util.List;
import java.util.concurrent.AbstractExecutorService;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Serial executor.
 * 
 * Serialize job execution before passing the jobs to a provided executor.
 */
public class SerialExecutor extends AbstractExecutorService implements CheckedExecutor {

	private static final Logger LOGGER = LoggerFactory.getLogger(SerialExecutor.class);

	/**
	 * Target executor to execute job serially.
	 */
	private final Executor executor;

	/**
	 * Owner thread, which currently executes the {@link #currentlyExecutedJob}.
	 */
	private final AtomicReference<Thread> owner = new AtomicReference<Thread>();

	/**
	 * Execution listener.
	 * 
	 * Called before and after executing a task.
	 * 
	 * @since 2.4
	 */
	private final AtomicReference<ExecutionListener> listener = new AtomicReference<ExecutionListener>();

	/**
	 * Queue for serialized jobs.
	 */
	private final BlockingQueue<Runnable> tasks = new LinkedBlockingQueue<>();

	/**
	 * Lock to protected simultaneous access.
	 */
	private final ReentrantLock lock = new ReentrantLock();

	/**
	 * Condition from {@link #lock} to wait for termination.
	 */
	private final Condition terminated = lock.newCondition();

	/**
	 * Currently executed job.
	 */
	private Runnable currentlyExecutedJob;

	/**
	 * Indicate shutdown.
	 */
	private boolean shutdown;

	/**
	 * Create serial executor
	 * 
	 * @param executor target executor. If {@code null}, the executor is
	 *            shutdown.
	 * @throws IllegalArgumentException if the executor is also a
	 *             {@link SerialExecutor}
	 */
	public SerialExecutor(final Executor executor) {
		if (executor == null) {
			shutdown = true;
		} else if (executor instanceof SerialExecutor) {
			throw new IllegalArgumentException("Sequences of SerialExecutors are not supported!");
		}
		this.executor = executor;
	}

	@Override
	public void execute(final Runnable command) {
		lock.lock();
		try {
			if (shutdown) {
				throw new RejectedExecutionException("SerialExecutor already shutdown!");
			}
			tasks.offer(command);
			if (currentlyExecutedJob == null) {
				scheduleNextJob();
			}
		} finally {
			lock.unlock();
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * {@link #currentlyExecutedJob} is used for the current job.
		 */
	@Override
	public void assertOwner() {
		final Thread me = Thread.currentThread();
		if (owner.get() != me) {
			final Thread thread = owner.get();
			if (thread == null) {
				throw new ConcurrentModificationException(this + " is not owned!");
			} else {
				throw new ConcurrentModificationException(this + " owned by " + thread.getName() + "!");
			}
		}
	}

	/**
	 * {@inheritDoc}
	 * 
	 * {@link #currentlyExecutedJob} is used for the current job.
		 */
	@Override
	public boolean checkOwner() {
		return owner.get() == Thread.currentThread();
	}

	/**
	 * Set current thread executing the {@link #currentlyExecutedJob}.
	 * 
	 * @throws ConcurrentModificationException if thread is already set.
	 */
	private void setOwner() {
		final Thread thread = owner.get();
		if (!owner.compareAndSet(null, Thread.currentThread())) {
			if (thread == null) {
				throw new ConcurrentModificationException(this + " was already owned!");
			} else {
				throw new ConcurrentModificationException(this + " already owned by " + thread.getName() + "!");
			}
		}
	}

	/**
	 * Remove current thread executing the {@link #currentlyExecutedJob}.
	 * 
	 * @throws ConcurrentModificationException if the current thread is not
	 *             executing the {@link #currentlyExecutedJob}.
	 */
	private void clearOwner() {
		if (!owner.compareAndSet(Thread.currentThread(), null)) {
			final Thread thread = owner.get();
			if (thread == null) {
				throw new ConcurrentModificationException(this + " is not owned, clear failed!");
			} else {
				throw new ConcurrentModificationException(this + " owned by " + thread.getName() + ", clear failed!");
			}
		}
	}

	/**
	 * {@inheritDoc}.
	 * 
	 * Doesn't shutdown the target executor {@link #executor}.
	 */
	@Override
	public void shutdown() {
		lock.lock();
		try {
			shutdown = true;
		} finally {
			lock.unlock();
		}
	}

	/**
	 * {@inheritDoc}.
	 * 
	 * Doesn't shutdown the target executor {@link #executor}.
	 * 
	 * @see #shutdownNow(Collection)
	 */
	@Override
	public List<Runnable> shutdownNow() {
		lock.lock();
		try {
			List<Runnable> pending = new ArrayList<>(tasks.size());
			shutdownNow(pending);
			return pending;
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Shutdown this executor and add all pending jobs from {@link #tasks} to
	 * the provided collection.
	 * 
	 * @param jobs collection to add pending jobs.
	 * @return number of added jobs
	 * @see #shutdownNow()
	 */
	public int shutdownNow(final Collection<Runnable> jobs) {
		lock.lock();
		try {
			shutdown();
			return tasks.drainTo(jobs);
		} finally {
			lock.unlock();
		}
	}

	@Override
	public boolean isShutdown() {
		lock.lock();
		try {
			return shutdown;
		} finally {
			lock.unlock();
		}
	}

	@Override
	public boolean isTerminated() {
		lock.lock();
		try {
			return shutdown && currentlyExecutedJob == null;
		} finally {
			lock.unlock();
		}
	}

	@Override
	public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
		lock.lock();
		try {
			long nanosTimeout = unit.toNanos(timeout);
			while (!shutdown || currentlyExecutedJob != null) {
				nanosTimeout = terminated.awaitNanos(nanosTimeout);
				if (nanosTimeout <= 0) {
					break;
				}
			}
			return shutdown && currentlyExecutedJob == null;
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Schedule next job from {@link #tasks}. {@link #setOwner()} and
	 * {@link #clearOwner()} before and after executing the job.
	 */
	private final void scheduleNextJob() {
		lock.lock();
		try {
			currentlyExecutedJob = tasks.poll();
			if (currentlyExecutedJob != null) {
				final Runnable command = currentlyExecutedJob;
				executor.execute(new Runnable() {

					@Override
					public void run() {
						try {
							setOwner();
							ExecutionListener current = listener.get();
							try {
								if (current != null) {
									current.beforeExecution();
								}
								command.run();
							} catch (Throwable t) {
								LOGGER.error("unexpected error occurred:", t);
							} finally {
								try {
									if (current != null) {
										current.afterExecution();
									}
								} catch (Throwable t) {
									LOGGER.error("unexpected error occurred after execution:", t);
								}
								clearOwner();
							}
						} finally {
							try {
								scheduleNextJob();
							} catch (RejectedExecutionException ex) {
								LOGGER.debug("shutdown?", ex);
							}
						}
					}
				});
			} else if (shutdown) {
				terminated.signalAll();
			}
		} finally {
			lock.unlock();
		}
	}

	/**
	 * Set execution listener.
	 * 
	 * Called before and after executing a task.
	 * 
	 * @param listener execution listener.
	 * @return previous execution listener
	 * @since 2.4
	 */
	public ExecutionListener setExecutionListener(ExecutionListener listener) {
		return this.listener.getAndSet(listener);
	}

	/**
	 * Execution listener.
	 * 
	 * Called before and after executing a task. The calling thread is the same
	 * as the the one executing the job.
	 * 
	 * @since 2.4
	 */
	public interface ExecutionListener {

		void beforeExecution();

		void afterExecution();
	}
}
