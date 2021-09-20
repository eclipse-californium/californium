/*******************************************************************************
 * Copyright (c) 2018 Sierra Wireless and others.
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
 *    Sierra Wireless - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.test;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CountingMessageObserver extends MessageObserverAdapter {
	private static final Logger LOGGER = LoggerFactory.getLogger(CountingMessageObserver.class);

	public AtomicInteger cancelCalls = new AtomicInteger();
	public AtomicInteger sentCalls = new AtomicInteger();
	public AtomicInteger loadCalls = new AtomicInteger();
	public AtomicInteger errorCalls = new AtomicInteger();
	public AtomicInteger responseErrorCalls = new AtomicInteger();

	@Override
	public void onSent(boolean retransmission) {
		int counter;
		synchronized (this) {
			counter = sentCalls.incrementAndGet();
			notifyAll();
		}
		LOGGER.info("{} messages sent!", counter);
	}

	@Override
	public void onCancel() {
		int counter;
		synchronized (this) {
			counter = cancelCalls.incrementAndGet();
			notifyAll();
		}
		LOGGER.info("{} messages cancelled!", counter);
	}

	@Override
	public void onResponse(Response response) {
		int counter;
		synchronized (this) {
			counter = loadCalls.incrementAndGet();
			notifyAll();
		}
		LOGGER.info("Received {}. Notification: {}", counter, response);
	}

	@Override
	public void onSendError(Throwable error) {
		int counter;
		synchronized (this) {
			counter = errorCalls.incrementAndGet();
			notifyAll();
		}
		LOGGER.info("{} errors!", counter);
	}

	@Override
	public void onResponseHandlingError(Throwable error) {
		int counter;
		synchronized (this) {
			counter = responseErrorCalls.incrementAndGet();
			notifyAll();
		}
		LOGGER.info("{} error-responses!", counter);
	}

	public boolean waitForSentCalls(final int counter, final long timeout, final TimeUnit unit)
			throws InterruptedException {
		return waitForCalls(counter, timeout, unit, sentCalls);
	}

	public boolean waitForCancelCalls(final int counter, final long timeout, final TimeUnit unit)
			throws InterruptedException {
		return waitForCalls(counter, timeout, unit, cancelCalls);
	}

	public boolean waitForLoadCalls(final int counter, final long timeout, final TimeUnit unit)
			throws InterruptedException {
		return waitForCalls(counter, timeout, unit, loadCalls);
	}

	public boolean waitForErrorCalls(final int counter, final long timeout, final TimeUnit unit)
			throws InterruptedException {
		return waitForCalls(counter, timeout, unit, errorCalls);
	}

	public boolean waitForResponseErrorCalls(final int counter, final long timeout, final TimeUnit unit)
			throws InterruptedException {
		return waitForCalls(counter, timeout, unit, responseErrorCalls);
	}

	private synchronized boolean waitForCalls(final int counter, final long timeout, final TimeUnit unit,
			AtomicInteger calls) throws InterruptedException {
		if (0 < timeout) {
			long end = System.nanoTime() + unit.toNanos(timeout);
			while (calls.get() < counter) {
				long left = TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime());
				if (0 < left) {
					wait(left);
				} else {
					break;
				}
			}
		}
		return calls.get() >= counter;
	}
}
