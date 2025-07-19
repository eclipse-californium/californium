/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - moved from org.eclipse.californium.core.test
 ******************************************************************************/
package org.eclipse.californium.core.test;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Counting coap handler for unit tests.
 * <p>
 * Counts callbacks, records responses, and forwards failures to main testing
 * thread on all "wait???" methods.
 */
public class CountingCoapHandler implements CoapHandler {

	private static final Logger LOGGER = LoggerFactory.getLogger(CountingCoapHandler.class);

	/**
	 * Current read index for {@link #waitOnLoad(long)}
	 */
	private int readIndex;
	/**
	 * Recorded responses.
	 */
	public List<CoapResponse> responses = new ArrayList<>();
	/**
	 * Flag to enable logging when failing.
	 * 
	 * @since 4.0
	 */
	public AtomicBoolean logOnFail = new AtomicBoolean(true);
	/**
	 * Counter for {@link #onLoad(CoapResponse)} calls.
	 */
	public AtomicInteger loadCalls = new AtomicInteger();
	/**
	 * Counter for {@link #onDrop(CoapResponse)} calls.
	 */
	public AtomicInteger dropCalls = new AtomicInteger();
	/**
	 * Counter for {@link #onError()} calls.
	 */
	public AtomicInteger errorCalls = new AtomicInteger();
	/**
	 * {@link AssertionError} or {@link RuntimeException} during call of
	 * {@link #assertLoad(CoapResponse)}.
	 */
	private volatile Throwable exception;

	public void logOnFail() {
		this.logOnFail.set(true);
	}

	public void noLogOnFail() {
		this.logOnFail.set(false);
	}

	@Override
	public final void onLoad(CoapResponse response) {
		int counter;
		synchronized (this) {
			counter = loadCalls.incrementAndGet();
			responses.add(response);
			try {
				assertLoad(response);
			} catch (AssertionError error) {
				LOGGER.error("Assert:", error);
				this.exception = error;
			} catch (RuntimeException exception) {
				LOGGER.error("Unexpected error:", exception);
				this.exception = exception;
			}
			notifyAll();
		}
		LOGGER.info("Received {}. Notification: {}", counter, response.advanced());
	}

	@Override
	public void onDrop(CoapResponse deprecatedNotify) {
		dropCalls.incrementAndGet();
	}

	/**
	 * Intended to be overwritten to check the response.
	 * <p>
	 * Failing asserts will be forwarded to main testing thread in all "wait???"
	 * methods.
	 * 
	 * @param response received response
	 */
	protected void assertLoad(CoapResponse response) {
	}

	@Override
	public final void onError() {
		int counter;
		synchronized (this) {
			counter = errorCalls.incrementAndGet();
			notifyAll();
		}
		LOGGER.info("{} Errors!", counter);
	}

	public CoapResponse getCoapResponse(int pos) {
		int size = responses.size();
		if (pos < 0) {
			pos = size + pos;
		}
		if (0 <= pos && pos < size) {
			return responses.get(pos);
		}
		return null;
	}

	public Response getResponse(int pos) {
		CoapResponse response = getCoapResponse(pos);
		return response == null ? null : response.advanced();
	}

	public int getOnLoadCalls() {
		return loadCalls.get();
	}

	public int getOnDropCalls() {
		return dropCalls.get();
	}

	public int getOnErrorCalls() {
		return errorCalls.get();
	}

	public Throwable getException() {
		return exception;
	}

	/**
	 * Wait for number of calls to {@link #onLoad(CoapResponse)}.
	 * <p>
	 * Also forwards {@link Error} or {@link RuntimeException} during execution
	 * of {@link #assertLoad(CoapResponse)} to the caller's thread.
	 * 
	 * @param counter number of expected calls
	 * @param timeout time to wait
	 * @param unit unit of time to wait
	 * @return {@code true}, if number of calls is reached in time,
	 *         {@code false}, otherwise.
	 * @throws InterruptedException if thread was interrupted.
	 * @throws Error if an error occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 * @throws RuntimeException if an runtime exception occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 */
	public boolean waitOnLoadCalls(int counter, long timeout, TimeUnit unit) throws InterruptedException {
		return waitOnCalls(counter, timeout, unit, loadCalls);
	}

	/**
	 * Wait for number of calls to {@link #onDrop(CoapResponse)}.
	 * 
	 * @param counter number of expected calls
	 * @param timeout time to wait
	 * @param unit unit of time to wait
	 * @return {@code true}, if number of calls is reached in time,
	 *         {@code false}, otherwise.
	 * @throws InterruptedException if thread was interrupted.
	 * @since 4.0
	 */
	public boolean waitOnDropCalls(int counter, long timeout, TimeUnit unit) throws InterruptedException {
		return waitOnCalls(counter, timeout, unit, dropCalls);
	}

	/**
	 * Wait for number of calls to {@link #onLoad(CoapResponse)} or
	 * {@link #onDrop(CoapResponse)}.
	 * 
	 * @param counter number of expected calls
	 * @param timeout time to wait
	 * @param unit unit of time to wait
	 * @return {@code true}, if number of calls is reached in time,
	 *         {@code false}, otherwise.
	 * @throws InterruptedException if thread was interrupted.
	 * @since 4.0
	 */
	public boolean waitOnLoadAndDropCalls(int counter, long timeout, TimeUnit unit) throws InterruptedException {
		return waitOnCalls(counter, timeout, unit, loadCalls, dropCalls);
	}

	/**
	 * Wait for number of calls to {@link #onError()}.
	 * <p>
	 * Also forwards {@link Error} or {@link RuntimeException} during execution
	 * of {@link #assertLoad(CoapResponse)} to the caller's thread.
	 * 
	 * @param counter number of expected calls
	 * @param timeout time to wait
	 * @param unit unit of time to wait
	 * @return {@code true}, if number of calls is reached in time,
	 *         {@code false}, otherwise.
	 * @throws InterruptedException if thread was interrupted.
	 * @throws Error if an error occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 * @throws RuntimeException if an runtime exception occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 */
	public boolean waitOnErrorCalls(int counter, long timeout, TimeUnit unit) throws InterruptedException {
		return waitOnCalls(counter, timeout, unit, errorCalls);
	}

	/**
	 * Wait for number of calls to {@link #onLoad(CoapResponse)} or
	 * {@link #onError()}.
	 * <p>
	 * Also forwards {@link Error} or {@link RuntimeException} during execution
	 * of {@link #assertLoad(CoapResponse)} to the caller's thread.
	 * 
	 * @param counter number of expected calls
	 * @param timeout time to wait
	 * @param unit unit of time to wait
	 * @return {@code true}, if number of calls is reached in time,
	 *         {@code false}, otherwise.
	 * @throws InterruptedException if thread was interrupted.
	 * @throws Error if an error occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 * @throws RuntimeException if an runtime exception occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 */
	public boolean waitOnCalls(final int counter, final long timeout, final TimeUnit unit) throws InterruptedException {
		return waitOnCalls(counter, timeout, unit, loadCalls, dropCalls, errorCalls);
	}

	/**
	 * Wait for number of calls.
	 * <p>
	 * Also forwards {@link Error} or {@link RuntimeException} during execution
	 * of {@link #assertLoad(CoapResponse)} to the caller's thread.
	 * 
	 * @param counter number of expected calls
	 * @param timeout time to wait
	 * @param unit unit of time to wait
	 * @param calls list of counters
	 * @return {@code true}, if number of calls is reached in time,
	 *         {@code false}, otherwise.
	 * @throws InterruptedException if thread was interrupted.
	 * @throws Error if an error occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 * @throws RuntimeException if an runtime exception occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 */
	private synchronized boolean waitOnCalls(final int counter, final long timeout, final TimeUnit unit,
			AtomicInteger... calls) throws InterruptedException {
		if (0 < timeout) {
			long end = System.nanoTime() + unit.toNanos(timeout);

			while (sum(calls) < counter) {
				long left = TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime());
				if (0 < left) {
					wait(left);
				} else {
					break;
				}
			}
		}
		int sum = sum(calls);
		if (sum < counter && logOnFail.get()) {
			LOGGER.warn("Waiting for {}, reached {}", counter, sum);
			for (CoapResponse response : responses) {
				LOGGER.warn("   received {}", response.getResponseText());
			}
		}
		return sum >= counter;
	}

	/**
	 * Check, if executing {@link #assertLoad(CoapResponse)} has thrown a
	 * {@link Error} or {@link RuntimeException} and forwards these to the
	 * caller's thread.
	 * 
	 * @throws Error if an error occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 * @throws RuntimeException if an runtime exception occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 * @see #exception
	 */
	private void forwardError() {
		Throwable exception = this.exception;
		if (exception != null) {
			if (exception instanceof Error) {
				throw (Error) exception;
			} else {
				throw (RuntimeException) exception;
			}
		}
	}

	/**
	 * Sum values of AtomicIntegers.
	 * <p>
	 * Also forwards {@link Error} or {@link RuntimeException} during execution
	 * of {@link #assertLoad(CoapResponse)} to the caller's thread.
	 * 
	 * @param calls list of AtomicInteger to add their values
	 * @return sum of AtomicInteger.
	 * @throws Error if an error occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 * @throws RuntimeException if an runtime exception occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 * @see #forwardError()
	 */
	private int sum(AtomicInteger... calls) {
		forwardError();
		int sum = 0;
		for (AtomicInteger counter : calls) {
			sum += counter.get();
		}
		return sum;
	}

	/**
	 * Wait for next response.
	 * <p>
	 * If the next response is already received, it's returned immediately. Also
	 * forwards {@link Error} or {@link RuntimeException} during execution of
	 * {@link #assertLoad(CoapResponse)} to the caller's thread.
	 * 
	 * @param timeout timeout in milliseconds. [@code 0}, don't wait.
	 * @return next response, or {@code null}, if no next response is available
	 *         within the provided timeout.
	 * @throws Error if an error occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 * @throws RuntimeException if an runtime exception occurred execution
	 *             {@link #assertLoad(CoapResponse)}
	 */
	public synchronized CoapResponse waitOnLoad(long timeout) {
		if (0 < timeout && responses.size() <= readIndex) {
			try {
				wait(timeout);
			} catch (InterruptedException e) {
			}
		}
		forwardError();
		if (readIndex < responses.size()) {
			return responses.get(readIndex++);
		}
		return null;
	}

	@Override
	public String toString() {
		StringBuilder builder = new StringBuilder();
		synchronized (this) {
			builder.append("loads:").append(loadCalls.get());
			builder.append(", read:").append(readIndex);
			builder.append(", errs:").append(errorCalls.get());
			if (dropCalls.get() > 0) {
				builder.append(", drops:").append(dropCalls.get());
			}
		}
		return builder.toString();
	}
}
