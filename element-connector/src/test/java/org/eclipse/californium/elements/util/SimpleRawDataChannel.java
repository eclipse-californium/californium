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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial implementation
 ******************************************************************************/
package org.eclipse.californium.elements.util;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;

/**
 * A simple raw data channel to access the incoming messages.
 */
public class SimpleRawDataChannel implements RawDataChannel {

	/**
	 * Number of expected raw data to await.
	 */
	private final CountDownLatch latchCalls;
	/**
	 * Queue of incoming raw data.
	 */
	private final LinkedBlockingQueue<RawData> incoming = new LinkedBlockingQueue<>();

	/**
	 * Create new raw data channel.
	 * 
	 * @param calls number of expected raw data .
	 */
	public SimpleRawDataChannel(int calls) {
		latchCalls = new CountDownLatch(calls);
	}

	/**
	 * Await that the provided number of raw data is reported.
	 * 
	 * @param timeoutMillis timeout in milliseconds.
	 * @return {@code true}, if the count reached zero, and {@code false}, if
	 *         the waiting time elapsed before the count reached zero
	 * @throws InterruptedException if the current thread is interrupted while
	 *             waiting
	 */
	public boolean await(long timeoutMillis) throws InterruptedException {
		return latchCalls.await(timeoutMillis, TimeUnit.MILLISECONDS);
	}

	@Override
	public void receiveData(RawData raw) {
		latchCalls.countDown();
		incoming.offer(raw);
	}

	public RawData poll(long timeout, TimeUnit unit) throws InterruptedException {
		return incoming.poll(timeout, unit);
	}
}
