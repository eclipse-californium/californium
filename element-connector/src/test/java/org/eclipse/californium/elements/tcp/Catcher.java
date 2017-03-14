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
 ******************************************************************************/
package org.eclipse.californium.elements.tcp;

import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;

import java.util.ArrayList;
import java.util.List;

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

	RawData getMessage(int index) {
		synchronized (lock) {
			return messages.get(index);
		}
	}
}
