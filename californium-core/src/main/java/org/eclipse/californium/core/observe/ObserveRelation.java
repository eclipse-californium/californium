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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - use configuration from
 *                                                    related exchange endpoint
 *    Achim Kraus (Bosch Software Innovations GmbH) - add canceled to suppress adding
 *                                                    already canceled relations again.
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ClockUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The ObserveRelation is a server-side control structure. It represents a
 * relation between a client endpoint and a resource on this server.
 */
public class ObserveRelation {

	/** The logger. */
	private final static Logger LOGGER = LoggerFactory.getLogger(ObserveRelation.class);

	private final long checkIntervalTime;
	private final int checkIntervalCount;

	private final ObservingEndpoint endpoint;

	/** The resource that is observed */
	private final Resource resource;

	/** The exchange that has established the observe relationship */
	private final Exchange exchange;

	private Response recentControlNotification;
	private Response nextControlNotification;

	private final String key;

	/*
	 * This value is false at first and must be set to true by the resource if
	 * it accepts the observe relation (the response code must be successful).
	 */
	/** Indicates if the relation is established */
	private volatile boolean established;
	/** Indicates if the relation is canceled */
	private volatile boolean canceled;

	private long interestCheckTimer = ClockUtil.nanoRealtime();
	private int interestCheckCounter = 1;

	/**
	 * Constructs a new observe relation.
	 * 
	 * @param endpoint the observing endpoint
	 * @param resource the observed resource
	 * @param exchange the exchange that tries to establish the observe relation
	 */
	public ObserveRelation(ObservingEndpoint endpoint, Resource resource, Exchange exchange) {
		if (endpoint == null)
			throw new NullPointerException();
		if (resource == null)
			throw new NullPointerException();
		if (exchange == null)
			throw new NullPointerException();
		this.endpoint = endpoint;
		this.resource = resource;
		this.exchange = exchange;
		Configuration config = exchange.getEndpoint().getConfig();
		checkIntervalTime = config.get(CoapConfig.NOTIFICATION_CHECK_INTERVAL_TIME, TimeUnit.NANOSECONDS);
		checkIntervalCount = config.get(CoapConfig.NOTIFICATION_CHECK_INTERVAL_COUNT);

		this.key = StringUtil.toString(getSource()) + "#" + exchange.getRequest().getTokenString();
		LOGGER.debug("Observe-relation, checks every {}ns or {} notifications.", checkIntervalTime, checkIntervalCount);
	}

	/**
	 * Returns his relation established state.
	 * 
	 * @return {@code true}, if this relation has been established,
	 *         {@code false}, otherwise
	 */
	public boolean isEstablished() {
		return established;
	}

	/**
	 * Sets the established field.
	 * 
	 * @throws IllegalStateException if the relation was already canceled.
	 */
	public void setEstablished() {
		boolean fail;
		synchronized (this) {
			fail = canceled;
			if (!fail) {
				established = true;
			}
		}
		if (fail) {
			throw new IllegalStateException(
					String.format("Could not establish observe relation %s with %s, already canceled (%s)!", getKey(),
							resource.getURI(), exchange));
		}
	}

	/**
	 * Check, if this relation is canceled.
	 * 
	 * @return {@code true}, if relation was canceled, {@code false}, otherwise.
	 */
	public boolean isCanceled() {
		return canceled;
	}

	/**
	 * Cleanup relation.
	 * 
	 * {@link #cancel()}, if {@link #isEstablished()}.
	 * 
	 * @since 3.0
	 */
	public void cleanup() {
		if (isEstablished()) {
			cancel();
		}
	}

	/**
	 * Cancel this observe relation.
	 * 
	 * This methods invokes the cancel methods of the resource and the endpoint.
	 * A last response must have been sent before. Otherwise the
	 * {@link Exchange} will be completed and fail that sending.
	 * 
	 * Note: calling this method outside the execution of the related
	 * {@link #exchange} may naturally cause indeterministic behavior.
	 * 
	 * @throws IllegalStateException if relation wasn't established.
	 */
	public void cancel() {
		cancel(true);
	}

	/**
	 * Cancel all observer relations that this server has established with this
	 * relation's endpoint.
	 */
	public void cancelAll() {
		endpoint.cancelAll();
	}

	/**
	 * Notifies the observing endpoint that the resource has been changed. This
	 * method makes the resource process the same request again.
	 */
	public void notifyObservers() {
		resource.handleRequest(exchange);
	}

	/**
	 * Gets the resource.
	 *
	 * @return the resource
	 */
	public Resource getResource() {
		return resource;
	}

	/**
	 * Gets the exchange.
	 *
	 * @return the exchange
	 */
	public Exchange getExchange() {
		return exchange;
	}

	/**
	 * Gets the source address of the observing endpoint.
	 *
	 * @return the source address
	 */
	public InetSocketAddress getSource() {
		return endpoint.getAddress();
	}

	/**
	 * Check, if notification is still requested.
	 * 
	 * Send notification as CON response in order to challenge the client to
	 * acknowledge the message.
	 * 
	 * @return {@code true}, to check the observer relation with a
	 *         CON-notification, {@code false}, otherwise.
	 */
	public boolean check() {
		long now = ClockUtil.nanoRealtime();
		boolean check;
		synchronized (this) {
			check = (++interestCheckCounter >= checkIntervalCount);
			if (check) {
				this.interestCheckTimer = now;
				this.interestCheckCounter = 0;
			}
		}
		if (check) {
			LOGGER.trace("Observe-relation check, {} notifications reached.", checkIntervalCount);
			return check;
		}
		synchronized (this) {
			check = (now - interestCheckTimer - checkIntervalTime) > 0;
			if (check) {
				this.interestCheckTimer = now;
				this.interestCheckCounter = 0;
			}
		}
		if (check) {
			LOGGER.trace("Observe-relation check, {}s interval reached.",
					TimeUnit.NANOSECONDS.toSeconds(checkIntervalTime));
		}
		return check;
	}

	/**
	 * Check, if sending the provided notification is postponed.
	 * 
	 * Postponed notification are kept and sent after the current notification.
	 * Calls {@link #send(Response)}, if not postponed.
	 * 
	 * @param response notification to check.
	 * @return {@code true}, if sending the notification is postponed,
	 *         {@code false}, if not.
	 * @since 3.0
	 */
	public boolean isPostponedNotification(Response response) {
		if (isInTransit(recentControlNotification)) {
			LOGGER.trace("in transit {}", recentControlNotification);
			if (nextControlNotification != null) {
				if (!nextControlNotification.isNotification()) {
					return true;
				}
				// complete deprecated response
				nextControlNotification.onTransferComplete();
			}
			nextControlNotification = response;
			return true;
		} else {
			recentControlNotification = response;
			nextControlNotification = null;
			send(response);
			return false;
		}
	}

	/**
	 * Get next notification.
	 * 
	 * Calls {@link #send(Response)} for next notification.
	 * 
	 * @param response current notification
	 * @param acknowledged {@code true}, if the current notification was
	 *            acknowledged, or {@code false}, on retransmission (caused by
	 *            missing acknowledged)
	 * @return next notification, or {@code null}, if no next notification is
	 *         available.
	 * @since 3.0
	 */
	public Response getNextNotification(Response response, boolean acknowledged) {
		Response next = null;
		if (recentControlNotification == response) {
			next = nextControlNotification;
			if (next != null) {
				// next may be null
				recentControlNotification = next;
				nextControlNotification = null;
				send(next);
			} else if (acknowledged) {
				// next may be null
				recentControlNotification = null;
				nextControlNotification = null;
			}
		}
		return next;
	}

	/**
	 * Send response for this relation.
	 * 
	 * If the response is no notification, {@link #cancel()} the relation
	 * internally without completing the exchange.
	 * 
	 * @param response response to sent.
	 * @since 3.0
	 */
	public void send(Response response) {
		if (!response.isNotification()) {
			cancel(false);
		}
	}

	/**
	 * Get key, identifying this observer relation.
	 * 
	 * Combination of source-address and token.
	 * 
	 * @return identifying key
	 */
	public String getKey() {
		return this.key;
	}

	/**
	 * Cancel this observe relation.
	 * 
	 * This methods invokes the cancel methods of the resource and the endpoint.
	 * 
	 * Note: calling this method outside the execution of the related
	 * {@link #exchange} may naturally cause indeterministic behavior.
	 * 
	 * @param complete {@code true}, to complete the exchange, {@code false}, to
	 *            not complete it.
	 * 
	 * @throws IllegalStateException if relation wasn't established.
	 * @since 3.0
	 */
	private void cancel(boolean complete) {
		boolean fail = false;
		boolean cancel = false;

		synchronized (this) {
			if (!canceled) {
				fail = !established;
				if (!fail) {
					canceled = true;
					established = false;
					cancel = true;
				}
			}
		}
		if (fail) {
			throw new IllegalStateException(String.format("Observe relation %s with %s not established (%s)!", getKey(),
					resource.getURI(), exchange));
		}
		if (cancel) {
			LOGGER.debug("Canceling observe relation {} with {} ({})", getKey(), resource.getURI(), exchange);
			resource.removeObserveRelation(this);
			endpoint.removeObserveRelation(this);
			if (complete) {
				exchange.executeComplete();
			}
		}
	}

	/**
	 * Returns {@code true}, if the specified response is still in transit. A
	 * response is in transit, if it has not yet been acknowledged, rejected or
	 * its current transmission has not yet timed out.
	 * 
	 * @param response notification to check.
	 * @return {@code true}, if notification is in transit, {@code false},
	 *         otherwise.
	 * @since 3.0
	 */
	private static boolean isInTransit(final Response response) {
		if (response == null || !response.isConfirmable()) {
			return false;
		}
		return !response.isAcknowledged() && !response.isTimedOut() && !response.isRejected();
	}

}
