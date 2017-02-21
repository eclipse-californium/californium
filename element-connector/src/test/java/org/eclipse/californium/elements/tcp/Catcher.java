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
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

class Catcher implements RawDataChannel {

	private final List<RawData> messages = new ArrayList<>();
	private final Object lock = new Object();

	@Override
	public void receiveData(RawData raw) {
		synchronized (lock) {
			messages.add(raw);
			lock.notifyAll();
		}
	}

	void blockUntilSize(int expectedSize) throws InterruptedException {
		synchronized (lock) {
			while (messages.size() < expectedSize) {
				lock.wait();
			}
		}
	}

	void blockUntilSize(int expectedSize, long timeout) throws InterruptedException {
		synchronized (lock) {
			timeout += TimeUnit.MILLISECONDS.convert(System.nanoTime(), TimeUnit.NANOSECONDS);
			while (messages.size() < expectedSize) {
				long time = timeout -= TimeUnit.MILLISECONDS.convert(System.nanoTime(), TimeUnit.NANOSECONDS);
				if (0 >= time)
					break;
				lock.wait(time);
			}
		}
	}

	RawData getMessage(int index) {
		synchronized (lock) {
			return messages.get(index);
		}
	}

	boolean hasMessage(int index) {
		synchronized (lock) {
			return index < messages.size();
		}
	}
}
