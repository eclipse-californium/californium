/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - add check of precondition for 
 *                                                    reregister. issue #56.
 *                                                    cleanup thread visibility and
 *                                                    response ordering. 
 *    Achim Kraus (Bosch Software Innovations GmbH) - cleanup proactive cancel
 *                                                    cancel the original observe request
 *                                                    may release the token, which is then
 *                                                    reused by the cancel request. Therefore
 *                                                    rely on the cleanup of the cancel request.
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - Use remove to cleanup canceled tasks.
 *                                                    fix issue #681
 *    Achim Kraus (Bosch Software Innovations GmbH) - use executors util
 *    Rogier Cobben - notification re-registration backoff fix, issue #917
 ******************************************************************************/
package org.eclipse.californium.core;

import java.util.function.BiConsumer;

import org.eclipse.californium.core.coap.ClientObserveRelation;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Endpoint;

/**
 * A CoapObserveRelation is a client-side control handle. It represents a CoAP
 * observe relation between a CoAP client and a resource on a server.
 * CoapObserveRelation provides a simple API to check whether a relation has
 * successfully established and to cancel or refresh the relation.
 */
public class CoapObserveRelation extends ClientObserveRelation {

	/** The current notification. */
	private volatile CoapResponse current = null;

	private volatile BiConsumer<Request, Response> notificationListener;

	/**
	 * Constructs a new CoapObserveRelation with the specified request.
	 *
	 * @param request the request
	 * @param endpoint the endpoint
	 * @throws IllegalArgumentException if endpoint has no executor
	 * @since 4.0 (removed executor from arguments)
	 */
	protected CoapObserveRelation(Request request, Endpoint endpoint) {
		super(request, endpoint);
	}

	/**
	 * Wait for first response.
	 * 
	 * Though {@link Request#waitForResponse(long)} may be executed asynchronous
	 * to the {@link #onResponse(Response)} processing of the notifications,
	 * {@link #getCurrent()} may still return {@code null}, while
	 * {@link Request#waitForResponse(long)} returns a response.
	 * 
	 * @param timeoutMillis timeout in milliseconds for the first response.
	 * @return first response, or {@code null}, if not response is reported
	 *         within the provided timeout.
	 * @since 3.0
	 */
	public synchronized CoapResponse waitForResponse(long timeoutMillis) {
		if (current == null) {
			try {
				wait(timeoutMillis);
			} catch (InterruptedException e) {
			}
		}
		return current;
	}

	/**
	 * Gets the current notification.
	 *
	 * @return the current notification, or {@code null}, if none has arrived
	 *         yet
	 * @see #waitForResponse(long)
	 */
	public CoapResponse getCurrent() {
		return current;
	}

	/**
	 * Marks this relation as canceled.
	 *
	 * @param canceled true if this relation has been canceled
	 */
	@Override
	protected void setCanceled(boolean canceled) {
		super.setCanceled(canceled);
		if (canceled) {

			if (notificationListener != null) {
				endpoint.removeNotificationListener(notificationListener);
			}
		}
	}

	public void setNotificationListener(BiConsumer<Request, Response>  listener) {
		notificationListener = listener;
	}

	/**
	 * Sets the current response or notification.
	 *
	 * Use {@link #orderer} to filter deprecated responses over UDP. Responses
	 * over TCP are already in order.
	 *
	 * @param response the response or notification
	 * @return {@code true}, response is accepted by {@link #orderer},
	 *         {@code false} otherwise.
	 */
	protected boolean onResponse(CoapResponse response) {
		boolean isNew = false;
		if (null != response) {
			isNew = super.onResponse(response.advanced());
			if (isNew) {
				synchronized (this) {
					current = response;
					notifyAll();
				}
			}
		}
		return isNew;
	}

	@Override
	public boolean onResponse(Response response) {
		if (super.onResponse(response)) {
			synchronized (this) {
				current = new CoapResponse(response);
				notifyAll();
			}
			return true;
		} else {
			return false;
		}
	}
}
