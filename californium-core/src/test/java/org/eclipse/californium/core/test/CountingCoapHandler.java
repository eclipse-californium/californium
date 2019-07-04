/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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

	private static final Logger LOGGER = LoggerFactory.getLogger(CountingCoapHandler.class.getCanonicalName());

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

	public boolean waitOnLoadCalls(final int counter, final long timeout, final TimeUnit unit)
			throws InterruptedException {
		return waitOnCalls(counter, timeout, unit, loadCalls);
	}

	public boolean waitOnErrorCalls(final int counter, final long timeout, final TimeUnit unit)
			throws InterruptedException {
		return waitOnCalls(counter, timeout, unit, errorCalls);
	}

	public boolean waitOnCalls(final int counter, final long timeout, final TimeUnit unit) throws InterruptedException {
		return waitOnCalls(counter, timeout, unit, loadCalls, errorCalls);
	}

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

	private void checkError() {
		if (exception != null) {
			if (exception instanceof Error) {
				throw (Error) exception;
			} else {
				throw (RuntimeException) exception;
			}
		}
	}

	private int sum(AtomicInteger... calls) {
		checkError();
		int sum = 0;
		for (AtomicInteger counter : calls) {
			sum += counter.get();
		}
		return sum;
	}

	public synchronized CoapResponse waitOnLoad(long timeout) {
		if (0 < timeout && !(readIndex < responses.size())) {
			try {
				wait(timeout);
			} catch (InterruptedException e) {
			}
		}
		checkError();
		if (readIndex < responses.size()) {
			return responses.get(readIndex++);
		}
		return null;
	}
}
