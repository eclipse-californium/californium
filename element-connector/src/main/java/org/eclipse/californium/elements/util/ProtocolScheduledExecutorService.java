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
package org.eclipse.californium.elements.util;

import java.util.concurrent.Callable;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Protocol scheduled executor service.
 * <p>
 * Californium 3 used in several functions two {@link ScheduledExecutorService}
 * for execution. The main was intended to be used only for very short and fast
 * tasks in a "non-blocking" way. The "scheduled" tasks of that main executor
 * are mainly intended to switch then to {@link SerialExecutor} to serialize
 * executing jobs in the scope of an (CoAP) {@code Exchange} or (DTLS)
 * {@code Connection}. The secondary executor is the intended for longer running
 * tasks, e.g. cleanup jobs. This long jobs must not execute too frequently and
 * may be delayed. To optimize the performance the main executor should be
 * created with
 * {@link ExecutorsUtil#newScheduledThreadPool(int, java.util.concurrent.ThreadFactory)}
 * and the secondary with
 * {@link ExecutorsUtil#newDefaultSecondaryScheduler(String)}.
 * <p>
 * In order to simplify the API for Californium 4, this behavior is mapped by
 * this interface into one executor. This replaces the two executors in several
 * functions. It may be provided with a custom implementation or by
 * {@link ExecutorsUtil#newProtocolScheduledThreadPool(int, java.util.concurrent.ThreadFactory)}
 * and
 * {@link ExecutorsUtil#newSingleThreadedProtocolExecutor(java.util.concurrent.ThreadFactory)}.
 * 
 * @since 4.0
 */
public interface ProtocolScheduledExecutorService extends ScheduledExecutorService {

	/**
	 * Creates and executes a one-shot background action that becomes enabled
	 * after the given delay.
	 * <p>
	 * Not intended to schedule large number of tasks.
	 * 
	 * @param command the task to execute
	 * @param delay the time from now to delay execution
	 * @param unit the time unit of the delay parameter
	 * @return a ScheduledFuture representing pending completion of the task and
	 *         whose {@code get()} method will return {@code null} upon
	 *         completion
	 * @throws RejectedExecutionException if the task cannot be scheduled for
	 *             execution
	 * @throws NullPointerException if command is null
	 */
	ScheduledFuture<?> scheduleBackground(Runnable command, long delay, TimeUnit unit);

	/**
	 * Creates and executes a background ScheduledFuture that becomes enabled
	 * after the given delay.
	 * <p>
	 * Not intended to schedule large number of tasks.
	 *
	 * @param callable the function to execute
	 * @param delay the time from now to delay execution
	 * @param unit the time unit of the delay parameter
	 * @param <V> the type of the callable's result
	 * @return a ScheduledFuture that can be used to extract result or cancel
	 * @throws RejectedExecutionException if the task cannot be scheduled for
	 *             execution
	 * @throws NullPointerException if callable is null
	 */
	<V> ScheduledFuture<V> scheduleBackground(Callable<V> callable, long delay, TimeUnit unit);

	/**
	 * Creates and executes a periodic background action that becomes enabled
	 * first after the given initial delay, and subsequently with the given
	 * period; that is executions will commence after {@code initialDelay} then
	 * {@code initialDelay+period}, then {@code initialDelay + 2 * period}, and
	 * so on. If any execution of the task encounters an exception, subsequent
	 * executions are suppressed. Otherwise, the task will only terminate via
	 * cancellation or termination of the executor. If any execution of this
	 * task takes longer than its period, then subsequent executions may start
	 * late, but will not concurrently execute.
	 * <p>
	 * Not intended to schedule large number of tasks.
	 *
	 * @param command the task to execute
	 * @param initialDelay the time to delay first execution
	 * @param period the period between successive executions
	 * @param unit the time unit of the initialDelay and period parameters
	 * @return a ScheduledFuture representing pending completion of the task,
	 *         and whose {@code get()} method will throw an exception upon
	 *         cancellation
	 * @throws RejectedExecutionException if the task cannot be scheduled for
	 *             execution
	 * @throws NullPointerException if command is null
	 * @throws IllegalArgumentException if period less than or equal to zero
	 */
	ScheduledFuture<?> scheduleBackgroundAtFixedRate(Runnable command, long initialDelay, long period, TimeUnit unit);

	/**
	 * Creates and executes a periodic background action that becomes enabled
	 * first after the given initial delay, and subsequently with the given
	 * delay between the termination of one execution and the commencement of
	 * the next. If any execution of the task encounters an exception,
	 * subsequent executions are suppressed. Otherwise, the task will only
	 * terminate via cancellation or termination of the executor.
	 * <p>
	 * Not intended to schedule large number of tasks.
	 *
	 * @param command the task to execute
	 * @param initialDelay the time to delay first execution
	 * @param delay the delay between the termination of one execution and the
	 *            commencement of the next
	 * @param unit the time unit of the initialDelay and delay parameters
	 * @return a ScheduledFuture representing pending completion of the task,
	 *         and whose {@code get()} method will throw an exception upon
	 *         cancellation
	 * @throws RejectedExecutionException if the task cannot be scheduled for
	 *             execution
	 * @throws NullPointerException if command is null
	 * @throws IllegalArgumentException if delay less than or equal to zero
	 */
	ScheduledFuture<?> scheduleBackgroundWithFixedDelay(Runnable command, long initialDelay, long delay, TimeUnit unit);

	/**
	 * Gets scheduled executor service for background tasks.
	 * 
	 * @return scheduled executor service for background tasks
	 */
	ScheduledExecutorService getBackgroundExecutor();
}
