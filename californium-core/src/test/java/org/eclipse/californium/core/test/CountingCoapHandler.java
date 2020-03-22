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
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Counting coap handler for unit tests.
 * 
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
	 * counter for {@link #onLoad(CoapResponse)} calls.
	 */
	public AtomicInteger loadCalls = new AtomicInteger();
	/**
	 * counter for {@link #onError()} calls.
	 */
	public AtomicInteger errorCalls = new AtomicInteger();
	/**
	 * {@link AssertionError} or {@link RuntimeException} during call of
	 * {@link #assertLoad(CoapResponse)}.
	 */
	private volatile Throwable exception;

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

	/**
	 * Intended to be overwritten to check the response.
	 * 
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

	public int getOnLoadCalls() {
		return loadCalls.get();
	}

	public int getOnErrorCalls() {
		return errorCalls.get();
	}

	public Throwable getException() {
		return exception;
	}

	/**
	 * Wait for number of calls to {@link #onLoad(CoapResponse)}.
	 * 
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
	 * Wait for number of calls to {@link #onError()}.
	 * 
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
	 * 
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
		return waitOnCalls(counter, timeout, unit, loadCalls, errorCalls);
	}

	/**
	 * Wait for number of calls.
	 * 
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
		return sum(calls) >= counter;
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
	 * 
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
	 * 
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
		}
		return builder.toString();
	}
}
