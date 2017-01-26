/*******************************************************************************
 * Copyright (c) 2016 Amazon Web Services.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - add "blockUntilSize" with
 *                                                 timeout and "hasMessage".
 *                                                 simplified synchronization. 
 *                                                 Used for testing none 
 *                                                 successful TLS connections.
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Test utility class for accessing received messages.
 */
public class Catcher implements RawDataChannel {

	/**
	 * Received messages.
	 * 
	 * @see #receiveData(RawData)
	 */
	private final List<RawData> messages = new ArrayList<>();

	@Override
	public synchronized void receiveData(RawData raw) {
		messages.add(raw);
		notifyAll();
	}

	/**
	 * Block until expected number of messages are received.
	 * 
	 * @param expectedSize expected number of messages
	 * @throws InterruptedException if thread is interrupted
	 * @see #blockUntilSize(int, long)
	 */
	public synchronized void blockUntilSize(int expectedSize) throws InterruptedException {
		while (messages.size() < expectedSize) {
			wait();
		}
	}

	/**
	 * Block until expected number of messages are received or timeout is
	 * reached.
	 * 
	 * @param expectedSize expected number of messages
	 * @param timeoutInMillis timeout in milliseconds
	 * @returns true, if expected messages are received within timeout, false,
	 *          otherwise.
	 * @throws InterruptedException if thread is interrupted
	 */
	public synchronized boolean blockUntilSize(int expectedSize, long timeoutInMillis) throws InterruptedException {
		timeoutInMillis += TimeUnit.MILLISECONDS.convert(System.nanoTime(), TimeUnit.NANOSECONDS);
		while (messages.size() < expectedSize) {
			long time = timeoutInMillis - TimeUnit.MILLISECONDS.convert(System.nanoTime(), TimeUnit.NANOSECONDS);
			if (0 >= time) {
				return false;
			}
			wait(time);
		}
		return true;
	}

	/**
	 * Get message by receive order.
	 * 
	 * @param index index of received messages. 0 for first.
	 * @return received message
	 * @throws IndexOutOfBoundsException if index is beyond received messages
	 */
	public synchronized RawData getMessage(int index) {
		return messages.get(index);
	}

	/**
	 * Check, if number of messages are received.
	 * 
	 * @param count number of received messages.
	 * @return true, if expected number of messages are received, false,
	 *         otherwise.
	 */
	public synchronized boolean hasMessages(int count) {
		return count < messages.size();
	}
}
