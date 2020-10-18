/*******************************************************************************
 * Copyright (c) 2020 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial implementation,
 *                    mainly copied from CoapObserveRelation
 ******************************************************************************/
package org.eclipse.californium.core.coap;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.ObserveNotificationOrderer;
import org.eclipse.californium.elements.EndpointContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A ClientObserveRelation is a client-side control handle. It represents a CoAP
 * observe relation between a CoAP client and a resource on a server.
 * ClientObserveRelation provides a simple API to check whether a relation has
 * successfully established and to cancel or refresh the relation.
 * 
 * @since 2.5
 */
public class ClientObserveRelation {

	/** The logger. */
	private static final Logger LOGGER = LoggerFactory.getLogger(ClientObserveRelation.class);

	/** A executor service to schedule re-registrations */
	private final ScheduledThreadPoolExecutor scheduler;

	/** The endpoint. */
	protected final Endpoint endpoint;

	/** The re-registration backoff duration [ms]. */
	private final long reregistrationBackoff;

	/**
	 * Indicates, that an observe request or a (proactive) cancel observe
	 * request is pending.
	 * 
	 * {@link #reregister()} is only effective, when no other request is already
	 * pending.
	 */
	private final AtomicBoolean requestPending = new AtomicBoolean(true);

	/** The handle to re-register for Observe notifications */
	private final AtomicReference<ScheduledFuture<?>> reregistrationHandle = new AtomicReference<ScheduledFuture<?>>();

	/** The request. */
	private volatile Request request;

	/** Indicates whether the relation has been canceled. */
	private volatile boolean canceled = false;
	/** Indicates whether a proactive cancel request is pending. */
	private volatile boolean proactiveCancel = false;

	/** The current notification. */
	private volatile Response current = null;

	/** The orderer. */
	private volatile ObserveNotificationOrderer orderer;

	/**
	 * Task to schedule {@link CoapObserveRelation#reregister()}.
	 */
	private final Runnable reregister = new Runnable() {

		@Override
		public void run() {
			reregister();
		}
	};

	/**
	 * Monitor pending request.
	 */
	private final MessageObserver pendingRequestObserver = new MessageObserverAdapter() {

		@Override
		public void onResponse(Response response) {
			next();
		}

		@Override
		public void onCancel() {
			next();
		}

		@Override
		protected void failed() {
			next();
		}

		private void next() {
			if (proactiveCancel) {
				sendCancelObserve();
			} else {
				requestPending.set(false);
			}
		}
	};

	/**
	 * Constructs a new ClientObserveRelation with the specified request.
	 *
	 * @param request the request
	 * @param endpoint the endpoint
	 * @param executor the executor to schedule the reregistration.
	 */
	public ClientObserveRelation(Request request, Endpoint endpoint, ScheduledThreadPoolExecutor executor) {
		this.request = request;
		this.endpoint = endpoint;
		this.orderer = new ObserveNotificationOrderer();
		this.reregistrationBackoff = endpoint.getConfig()
				.getLong(NetworkConfig.Keys.NOTIFICATION_REREGISTRATION_BACKOFF);
		this.scheduler = executor;
		this.request.addMessageObserver(pendingRequestObserver);
		this.request.setProtectFromOffload();
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
		Response response = current;
		if (response != null && !response.getOptions().hasObserve()) {
			throw new IllegalStateException("observe not supported by CoAP server!");
		}
		if (isCanceled()) {
			throw new IllegalStateException("observe already canceled!");
		}
		if (requestPending.compareAndSet(false, true)) {
			Request refresh = Request.newGet();
			EndpointContext destinationContext = response != null ? response.getSourceContext()
					: request.getDestinationContext();
			refresh.setDestinationContext(destinationContext);
			// use same Token
			refresh.setToken(request.getToken());
			// copy options
			refresh.setOptions(request.getOptions());

			refresh.setMaxResourceBodySize(request.getMaxResourceBodySize());
			if (request.isUnintendedPayload()) {
				refresh.setUnintendedPayload();
				refresh.setPayload(request.getPayload());
			}

			// use same message observers
			for (MessageObserver observer : request.getMessageObservers()) {
				if (observer instanceof InternalMessageObserver) {
					if (((InternalMessageObserver) observer).isInternal()) {
						continue;
					}
				}
				request.removeMessageObserver(observer);
				refresh.addMessageObserver(observer);
			}

			this.request = refresh;
			// update request in observe handle for correct cancellation
			// reset orderer to accept any sequence number since server
			// might have rebooted
			this.orderer = new ObserveNotificationOrderer();

			endpoint.sendRequest(refresh);

			return true;
		} else {
			return false;
		}
	}

	/**
	 * Send request with option "cancel observe" (GET with Observe=1).
	 */
	private void sendCancelObserve() {
		proactiveCancel = false;
		Response response = current;
		Request request = this.request;
		EndpointContext destinationContext = response != null ? response.getSourceContext()
				: request.getDestinationContext();

		Request cancel = Request.newGet();
		cancel.setDestinationContext(destinationContext);
		// use same Token
		cancel.setToken(request.getToken());
		// copy options
		cancel.setOptions(request.getOptions());
		// set Observe to cancel
		cancel.setObserveCancel();

		cancel.setMaxResourceBodySize(request.getMaxResourceBodySize());
		if (request.isUnintendedPayload()) {
			cancel.setUnintendedPayload();
			cancel.setPayload(request.getPayload());
		}

		// use same message observers
		for (MessageObserver observer : request.getMessageObservers()) {
			if (observer instanceof InternalMessageObserver) {
				if (((InternalMessageObserver) observer).isInternal()) {
					continue;
				}
			}
			request.removeMessageObserver(observer);
			cancel.addMessageObserver(observer);
		}

		endpoint.sendRequest(cancel);
	}

	/**
	 * Cancel observation. Cancel pending request of this observation and stop
	 * reregistrations.
	 */
	private void cancel() {
		endpoint.cancelObservation(request.getToken());
		setCanceled(true);
	}

	/**
	 * Proactive Observe cancellation: Cancel the observe relation by sending a
	 * GET with Observe=1.
	 */
	public void proactiveCancel() {
		// stop reregistration
		cancel();
		proactiveCancel = true;
		if (requestPending.compareAndSet(false, true)) {
			sendCancelObserve();
		}
		// cancel observe relation
	}

	/**
	 * Reactive Observe cancellation: Cancel the observe relation by forgetting,
	 * which will trigger a RST. For TCP, {{@link #proactiveCancel()} will be
	 * executed.
	 */
	public void reactiveCancel() {
		Request request = this.request;
		if (CoAP.isTcpScheme(request.getScheme())) {
			LOGGER.info("change to cancel the observe {} proactive over TCP.", request.getTokenString());
			proactiveCancel();
		} else {
			// cancel old ongoing request
			request.cancel();
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
	public Response getCurrentResponse() {
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
	public boolean onResponse(Response response) {
		boolean isNew = false;
		if (null != response) {
			Integer observe = response.getOptions().getObserve();
			// check, if observation is still ongoing
			boolean prepareNext = observe != null && !isCanceled();
			isNew = orderer.isNew(response);
			if (isNew) {
				current = response;
			} else if (prepareNext) {
				// renew preparation also for reregistration responses,
				// which may still be unchanged
				prepareNext = orderer.getCurrent() == observe;
			}
			if (prepareNext) {
				prepareReregistration(response);
			}
		}
		return isNew;
	}

	/**
	 * Check, if request matches observe relation.
	 * 
	 * @param request request to match. Must be sent using the endpoint provided
	 *            when creating this relation.
	 * @return {@code true}, if matched, {@code false}, if not.
	 */
	public boolean matchRequest(Request request) {
		return this.request.getToken().equals(request.getToken());
	}

	private void setReregistrationHandle(ScheduledFuture<?> reregistrationHandle) {
		ScheduledFuture<?> previousHandle = this.reregistrationHandle.getAndSet(reregistrationHandle);
		if (previousHandle != null) {
			if (previousHandle instanceof Runnable) {
				scheduler.remove((Runnable) previousHandle);
			} else {
				previousHandle.cancel(false);
			}
		}
	}

	private void prepareReregistration(Response response) {
		long timeout = response.getOptions().getMaxAge() * 1000 + this.reregistrationBackoff;
		ScheduledFuture<?> f = scheduler.schedule(reregister, timeout, TimeUnit.MILLISECONDS);
		setReregistrationHandle(f);
	}
}
