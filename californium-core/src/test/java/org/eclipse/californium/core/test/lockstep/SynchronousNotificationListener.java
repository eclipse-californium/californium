/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.observe.NotificationListener;

public class SynchronousNotificationListener implements NotificationListener {

	private Request request; // request to listen
	private Response response;
	private Object lock = new Object();
	private AtomicInteger notificationCount = new AtomicInteger();

	public SynchronousNotificationListener() {
	}

	public SynchronousNotificationListener(final Request req) {
		request = req;
	}

	/**
	 * Wait until a response is received or the request was cancelled/rejected.
	 * 
	 * @return the response or null if waiting time elapses or if request is
	 *         cancelled/rejected.
	 */
	public Response waitForResponse(final long timeoutInMs) throws InterruptedException {
		Response r;
		synchronized (lock) {
			if (response != null)
				r = response;
			else {
				lock.wait(timeoutInMs);
				r = response;
			}
			response = null;
		}
		return r;
	}

	@Override
	public void onNotification(final Request req, final Response resp) {
		if (request == null || Arrays.equals(request.getToken(), req.getToken())
				&& request.getDestinationEndpoint().equals(req.getDestinationEndpoint())) {
			synchronized (lock) {
				response = resp;
				notificationCount.incrementAndGet();
				lock.notifyAll();
			}
		}
	}

	public int getNotificationCount() {
		return notificationCount.get();
	}

	public void resetNotificationCount() {
		notificationCount.set(0);
	}
}
