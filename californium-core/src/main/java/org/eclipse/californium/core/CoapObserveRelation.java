/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - add check of precondition for 
 *                                                    reregister. issue #56.
 *                                                    cleanup thread visibility and
 *                                                    response ordering. 
 ******************************************************************************/
package org.eclipse.californium.core;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MessageObserver;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.observe.ObserveNotificationOrderer;
import org.eclipse.californium.elements.util.DaemonThreadFactory;

/**
 * A CoapObserveRelation is a client-side control handle. It represents a CoAP
 * observe relation between a CoAP client and a resource on a server.
 * CoapObserveRelation provides a simple API to check whether a relation has
 * successfully established and to cancel or refresh the relation.
 */
public class CoapObserveRelation {

	/** The logger. */
	private static final Logger LOGGER = Logger.getLogger(CoapObserveRelation.class.getCanonicalName());

	/** A executor service to schedule re-registrations */
	private static final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(//
			new DaemonThreadFactory("CoapObserveRelation#")); //$NON-NLS-1$

	/** The endpoint. */
	private final Endpoint endpoint;

	/**
	 * Indicates, that an observe request is pending.
	 * 
	 * {@ink #reregister()} is only effective, when no observe request is
	 * already pending.
	 */
	private final AtomicBoolean registrationPending = new AtomicBoolean(true);

	/** The handle to re-register for Observe notifications */
	private final AtomicReference<ScheduledFuture<?>> reregistrationHandle = new AtomicReference<ScheduledFuture<?>>();

	/** The request. */
	private volatile Request request;

	/** Indicates whether the relation has been canceled. */
	private volatile boolean canceled = false;

	/** The current notification. */
	private volatile CoapResponse current = null;

	/** The orderer. */
	private volatile ObserveNotificationOrderer orderer;

	/**
	 * Constructs a new CoapObserveRelation with the specified request.
	 *
	 * @param request the request
	 * @param endpoint the endpoint
	 */
	protected CoapObserveRelation(Request request, Endpoint endpoint) {
		this.request = request;
		this.endpoint = endpoint;
		this.orderer = new ObserveNotificationOrderer();
	}

	/**
	 * Refreshes the Observe relationship with a new GET request with same token
	 * and options. The method also resets the notification orderer, since the
	 * server might have rebooted and started the observe sequence number from
	 * the beginning.
	 * 
	 * @return {@code true}, if reregister request is sent, {@code false},
	 *         otherwise.
	 * @throws IllegalStateException if the request is already canceled or the
	 *             CoAP server is not supported.
	 */
	public boolean reregister() {
		Request request = this.request;
		if (request.isCanceled()) {
			throw new IllegalStateException("observe request already canceled! token " + request.getTokenString());
		}
		CoapResponse response = current;
		if (response != null && !response.getOptions().hasObserve()) {
			throw new IllegalStateException("observe not supported by CoAP server!");
		}
		if (isCanceled()) {
			throw new IllegalStateException("observe already canceled!");
		}
		if (registrationPending.compareAndSet(false, true)) {
			Request refresh = Request.newGet();
			refresh.setDestination(request.getDestination());
			refresh.setDestinationPort(request.getDestinationPort());
			// use same Token
			refresh.setToken(request.getToken());
			// copy options, but set Observe to zero
			refresh.setOptions(request.getOptions());

			// use same message observers
			for (MessageObserver mo : request.getMessageObservers()) {
				request.removeMessageObserver(mo);
				refresh.addMessageObserver(mo);
			}

			this.request = refresh;
			endpoint.sendRequest(refresh);

			// update request in observe handle for correct cancellation
			// reset orderer to accept any sequence number since server
			// might have rebooted
			this.orderer = new ObserveNotificationOrderer();
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Send request with option "cancel observe" (GET with Observe=1).
	 */
	private void sendCancelObserve() {
		Request request = this.request;
		Request cancel = Request.newGet();
		cancel.setDestination(request.getDestination());
		cancel.setDestinationPort(request.getDestinationPort());
		// use same Token
		cancel.setToken(request.getToken());
		// copy options, but set Observe to cancel
		cancel.setOptions(request.getOptions());
		cancel.setObserveCancel();

		// dispatch final response to the same message observers
		for (MessageObserver mo : request.getMessageObservers()) {
			cancel.addMessageObserver(mo);
		}

		endpoint.sendRequest(cancel);
	}

	/**
	 * Cancel observer.
	 */
	private void cancel() {
		Request request = this.request;
		request.cancel();
		setCanceled(true);
	}

	/**
	 * Proactive Observe cancellation: Cancel the observe relation by sending a
	 * GET with Observe=1.
	 */
	public void proactiveCancel() {
		sendCancelObserve();

		// cancel old ongoing request
		cancel();
	}

	/**
	 * Reactive Observe cancellation: Cancel the observe relation by forgetting,
	 * which will trigger a RST. For TCP, {{@link #proactiveCancel()} will be
	 * executed.
	 */
	public void reactiveCancel() {
		Request request = this.request;
		if (CoAP.isTcpScheme(request.getScheme())) {
			LOGGER.log(Level.INFO, "Change to cancel the observe {0} proactive over TCP.", request.getTokenString());
			proactiveCancel();
		} else {
			// cancel old ongoing request
			cancel();
		}
	}

	/**
	 * Checks if the relation has been canceled.
	 *
	 * @return true, if the relation has been canceled
	 */
	public boolean isCanceled() {
		return canceled;
	}

	/**
	 * Gets the current notification or null if none has arrived yet.
	 *
	 * @return the current notification
	 */
	public CoapResponse getCurrent() {
		return current;
	}

	/**
	 * Marks this relation as canceled.
	 *
	 * @param canceled true if this relation has been canceled
	 */
	protected void setCanceled(boolean canceled) {
		this.canceled = canceled;

		if (this.canceled) {
			setReregistrationHandle(null);
		}
	}

	/**
	 * Sets the current response or notification.
	 *
	 * Use {@link #orderer} to filter deprecated responses.
	 *
	 * @param response the response or notification
	 * @return {@code true}, response is accepted by {@link #orderer},
	 *         {@code false} otherwise.
	 */
	protected boolean onResponse(CoapResponse response) {
		if (null != response && orderer.isNew(response.advanced())) {
			current = response;
			prepareReregistration(response, 2000);
			registrationPending.set(false);
			return true;
		} else {
			return false;
		}
	}

	private void setReregistrationHandle(ScheduledFuture<?> reregistrationHandle) {
		ScheduledFuture<?> previousHandle = this.reregistrationHandle.getAndSet(reregistrationHandle);
		if (previousHandle != null) {
			previousHandle.cancel(false);
		}
	}

	private void prepareReregistration(CoapResponse response, long backoff) {
		if (!isCanceled()) {
			long timeout = response.getOptions().getMaxAge() * 1000 + backoff;
			ScheduledFuture<?> f = scheduler.schedule(new Runnable() {
	
				@Override
				public void run() {
					reregister();
				}
			}, timeout, TimeUnit.MILLISECONDS);
			setReregistrationHandle(f);
		}
	}
}
