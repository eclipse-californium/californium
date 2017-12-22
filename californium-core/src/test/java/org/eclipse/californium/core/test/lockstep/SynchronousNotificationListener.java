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
 *    Achim Kraus (Bosch Software Innovations GmbH) - collect notifies for log.
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import java.util.LinkedList;
import java.util.List;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.observe.NotificationListener;

public class SynchronousNotificationListener implements NotificationListener {

	private final Request request; // request to listen
	private Response response;
	private List<Response> notifies = new LinkedList<Response>();
	private Object lock = new Object();

	public SynchronousNotificationListener() {
		request = null;
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
		if (request == null || request.getToken().equals(req.getToken())) {
			synchronized (lock) {
				notifies.add(resp);
				response = resp;
				lock.notifyAll();
			}
		}
	}

	public int getNotificationCount() {
		synchronized (lock) {
			return notifies.size();
		}
	}

	public void resetNotificationCount() {
		synchronized (lock) {
			notifies.clear();
		}
	}

	public void log() {
		synchronized (lock) {
			if (notifies.isEmpty()) {
				if (request == null) {
					System.out.println("No notify received.");
				} else {
					System.out.println("No notify received for " + request);
				}
				return;
			}
			if (notifies.size() == 1) {
				if (request == null) {
					System.out.println("Notify received. " + notifies.get(0));
				} else {
					System.out.println("Notify received for " + request);
					System.out.println("   " + notifies.get(0));
				}
				return;
			}
			int counter = 1;
			if (request == null) {
				System.out.println(notifies.size() + " Notifies received.");
			} else {
				System.out.println(notifies.size() + " Notifies received for " + request);
			}
			for (Response resp : notifies) {
				System.out.println("[" + counter + "]: " + resp);
				++counter;
			}
		}
	}
}
