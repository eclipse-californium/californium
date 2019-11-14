/*******************************************************************************
 * Copyright (c) 2016 Amazon Web Services.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - add "blockUntilSize" with
 *                                                 timeout and "hasMessage". 
 * Achim Kraus (Bosch Software Innovations GmbH) - make methods public
 ******************************************************************************/
package org.eclipse.californium.elements.tcp.netty;

import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;

import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class Catcher implements RawDataChannel {

	private final List<RawData> messages = new ArrayList<>();
	private final Object lock = new Object();

	@Override
	public void receiveData(RawData raw) {
		synchronized (lock) {
			messages.add(raw);
			lock.notifyAll();
		}
	}

	public boolean blockUntilSize(int expectedSize, long timeout) throws InterruptedException {
		long end = timeout + TimeUnit.MILLISECONDS.convert(System.nanoTime(), TimeUnit.NANOSECONDS);
		synchronized (lock) {
			while (messages.size() < expectedSize) {
				long time = end - TimeUnit.MILLISECONDS.convert(System.nanoTime(), TimeUnit.NANOSECONDS);
				if (0 >= time) {
					break;
				}
				lock.wait(time);
			}
			return messages.size() >= expectedSize;
		}
	}

	public RawData getMessage(int index) {
		synchronized (lock) {
			return messages.get(index);
		}
	}

	/**
	 * Get endpoint context of message with provided index.
	 * 
	 * @param index index o f message
	 * @return endpoint context
	 * @throws IndexOutOfBoundsException, if index is greater than the number of
	 *             received messages
	 */
	public EndpointContext getEndpointContext(int index) {
		RawData msg = getMessage(index);
		assertThat(msg, is(notNullValue()));
		EndpointContext context = msg.getEndpointContext();
		assertThat(context, is(notNullValue()));
		return context;
	}

	public boolean hasMessage(int index) {
		synchronized (lock) {
			return index < messages.size();
		}
	}
}
