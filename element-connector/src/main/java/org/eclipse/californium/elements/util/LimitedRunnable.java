/*******************************************************************************
 * Copyright (c) 2022 Contributors to the Eclipse Foundation.
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
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Limited jobs.
 *
 * Limits pending jobs based on counters.
 * 
 * Note: for proper operation, ensure the at the end of
 * {@link Runnable#run()} the {@link LimitedRunnable#onDequeueing()} is
 * called.
 * 
 * <pre>
 *	public void run() {
 *		try {
 *			if (running.get() &amp;&amp; connection.isExecuting()) {
 *				// process
 *			}
 *		} finally {
 *			onDequeueing();
 *		}
 *	}
 * </pre>
 * 
 * @since 3.7
 */
public abstract class LimitedRunnable implements Runnable {

	/**
	 * Down counter to limit pending jobs.
	 */
	private final AtomicInteger counter;
	/**
	 * Indicator for overflows. {@code true}, if the counter indicates an
	 * overflow, {@code false}, otherwise.
	 */
	private volatile boolean overflow;

	/**
	 * Create job limited by the provided counter
	 * 
	 * @param counter counter in count-down mode
	 */
	public LimitedRunnable(AtomicInteger counter) {
		this.counter = counter;
	}

	/**
	 * Queue job.
	 * 
	 * @throws RejectedExecutionException if limit is exceeded
	 */
	public void onQueueing() {
		if (counter.decrementAndGet() < 0) {
			overflow = true;
			throw new RejectedExecutionException("queue overflow!");
		}
	}

	/**
	 * Dequeue job.
	 */
	public void onDequeueing() {
		counter.incrementAndGet();
	}

	/**
	 * Checks, if queueing this job causes an counter overflow.
	 * 
	 * @return {@code true}, if the counter indicates an overflow,
	 *         {@code false}, otherwise.
	 */
	public boolean isOverflown() {
		return overflow;
	}

	/**
	 * Handles {@code RejectedExecutionException}
	 * @param ex the thrown exception
	 *
	 * @since 3.8
	 */
	public void onError(RejectedExecutionException ex) {};

	/**
	 * Execute this job.
	 * 
	 * @param executor executor to execute jobs.
	 */
	public void execute(Executor executor) {
		try {
			onQueueing();
			executor.execute(this);
		} catch (RejectedExecutionException ex) {
			onDequeueing();
			onError(ex);
			throw ex;
		}
	}
}