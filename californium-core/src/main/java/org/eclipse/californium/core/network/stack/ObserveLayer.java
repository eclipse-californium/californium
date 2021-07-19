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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use new MID for new notifications
 *                                                    add NON notifications only to relation,
 *                                                    if they are really sent as NON.
 *                                                    (issue #258, RFC Section 4.5.2 of RFC 7641)
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix copy & paste error
 *                                                    replace "response" with "next" in
 *                                                    onAcknowledgement()
 *    Achim Kraus (Bosch Software Innovations GmbH) - complete old notification
 *                                                    exchange
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove "is last", not longer meaningful
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove synchronization and use
 *                                                    striped exchange execution instead.
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace striped executor
 *                                                    with serial executor
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * UDP observe layer.
 */
public class ObserveLayer extends AbstractLayer {

	private static final Logger LOGGER = LoggerFactory.getLogger(ObserveLayer.class);

	/**
	 * Creates a new observe layer for a configuration.
	 * 
	 * @param config The configuration values to use.
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public ObserveLayer(final Configuration config) {
		// so far no configuration values for this layer
	}

	@Override
	public void sendResponse(final Exchange exchange, final Response response) {

		final ObserveRelation relation = exchange.getRelation();

		if (relation != null && relation.isEstablished()) {

			if (exchange.getRequest().isAcknowledged() || exchange.getRequest().getType() == Type.NON) {
				// Transmit errors as CON
				if (!ResponseCode.isSuccess(response.getCode())) {
					LOGGER.debug("response has error code {} and must be sent as CON", response.getCode());
					response.setType(Type.CON);
					relation.cancel();
				} else {
					// Make sure that every now and than a CON is mixed within
					if (relation.check()) {
						LOGGER.debug("observe relation check requires the notification to be sent as CON");
						response.setType(Type.CON);
					} else {
						// By default use NON, but do not override resource
						// decision
						if (response.getType() == null) {
							response.setType(Type.NON);
						}
					}
				}
			}

			/*
			 * Only one Confirmable message is allowed to be in transit. A CON
			 * is in transit as long as it has not been acknowledged, rejected,
			 * or timed out. All further notifications are postponed here. If a
			 * former CON is acknowledged or timeouts, it starts the freshest
			 * notification (In case of a timeout, it keeps the retransmission
			 * counter). When a fresh/younger notification arrives but must be
			 * postponed we forget any former notification.
			 */
			if (response.getType() == Type.CON) {
				prepareSelfReplacement(exchange, response);
			}

			// The decision whether to postpone this notification or not and the
			// decision which notification is the freshest to send next must be
			// synchronized
			if (relation.isPostponedNotification(response)) {
				LOGGER.debug("a former notification is still in transit. Postponing {}", response);
				// do not send now
				return;
			}

		} // else no observe was requested or the resource does not allow it
		lower().sendResponse(exchange, response);
	}

	@Override
	public void receiveResponse(final Exchange exchange, final Response response) {

		if (response.isNotification() && exchange.getRequest().isCanceled()) {
			// The request was canceled and we no longer want notifications
			LOGGER.debug("rejecting notification for canceled Exchange");
			EmptyMessage rst = EmptyMessage.newRST(response);
			sendEmptyMessage(exchange, rst);
			// Matcher sets exchange as complete when RST is sent
		} else {
			// No observe option in response => always deliver
			upper().receiveResponse(exchange, response);
		}
	}

	@Override
	public void receiveEmptyMessage(final Exchange exchange, final EmptyMessage message) {
		// NOTE: We could also move this into the MessageObserverAdapter from
		// sendResponse into the method rejected().
		if (message.getType() == Type.RST && exchange.getOrigin() == Origin.REMOTE) {
			// The response has been rejected
			ObserveRelation relation = exchange.getRelation();
			if (relation != null) {
				relation.cancel();
			} // else there was no observe relation ship and this layer ignores
				// the rst
		}
		upper().receiveEmptyMessage(exchange, message);
	}

	private void prepareSelfReplacement(Exchange exchange, Response response) {
		response.addMessageObserver(new NotificationController(exchange, response));
	}

	/**
	 * Sends the next CON as soon as the former CON is no longer in transit.
	 */
	private class NotificationController extends MessageObserverAdapter {

		private final Exchange exchange;
		private final Response response;

		public NotificationController(Exchange exchange, Response response) {
			this.exchange = exchange;
			this.response = response;
		}

		@Override
		public void onAcknowledgement() {
			exchange.execute(new Runnable() {

				@Override
				public void run() {
					ObserveRelation relation = exchange.getRelation();
					final Response next = relation.getNextNotification(response, true);
					if (next != null) {
						LOGGER.debug("notification has been acknowledged, send the next one");
						if (relation.isCanceled()) {
							next.cancel();
						} else {
							ObserveLayer.super.sendResponse(exchange, next);
						}
					}
				}
			});
		}

		@Override
		public void onRetransmission() {
			// called within the exchange executor context.
			ObserveRelation relation = exchange.getRelation();
			Response next = relation.getNextNotification(response, false);
			if (relation.isCanceled()) {
				response.cancel();
				if (next != null) {
					next.cancel();
					next = null;
				}
			}
			if (next != null) {
				LOGGER.debug("notification has timed out and there is a fresher notification for the retransmission");
				// Convert all notification retransmissions to CON
				if (next.getType() != Type.CON) {
					next.setType(Type.CON);
					prepareSelfReplacement(exchange, next);
				}
				// Cancel the original retransmission and
				// send the fresh notification here
				response.cancel();
				ObserveLayer.super.sendResponse(exchange, next);
			}
		}

		@Override
		public void onTimeout() {
			ObserveRelation relation = exchange.getRelation();
			LOGGER.info("notification for token [{}] timed out. Canceling all relations with source [{}]",
					relation.getExchange().getRequest().getToken(), StringUtil.toLog(relation.getSource()));
			relation.cancelAll();
		}

		// Cancellation on RST is done in receiveEmptyMessage()
	}
}
