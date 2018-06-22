/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.test;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapResponse;

public class CountingHandler implements CoapHandler {

	public AtomicInteger loadCalls = new AtomicInteger();
	public AtomicInteger errorCalls = new AtomicInteger();

	@Override
	public void onLoad(CoapResponse response) {
		int counter;
		synchronized (this) {
			counter = loadCalls.incrementAndGet();
			notifyAll();
		}
		System.out.println("Received " + counter + ". Notification: " + response.advanced());
	}

	@Override
	public void onError() {
		int counter;
		synchronized (this) {
			counter = errorCalls.incrementAndGet();
			notifyAll();
		}
		System.out.println(counter + " Errors!");
	}

	public boolean waitForLoadCalls(final int counter, final long timeout, final TimeUnit unit)
			throws InterruptedException {
		return waitForCalls(counter, timeout, unit, loadCalls);
	}

	public boolean waitForErrorCalls(final int counter, final long timeout, final TimeUnit unit)
			throws InterruptedException {
		return waitForCalls(counter, timeout, unit, errorCalls);
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
