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
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Bosch Software Innovations GmbH - use correlation context to improve matching
 *                                      of Response(s) to Request (fix GitHub issue #1)
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace isResponseRelatedToRequest
 *                                                    with CorrelationContextMatcher
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove obsolete ExchangeObserver
 *                                                    from matchNotifyResponse. Don't
 *                                                    remove exchange by MID on notify. 
 *                                                    Add Exchange for save remove.
 *    Achim Kraus (Bosch Software Innovations GmbH) - make exchangeStore final
 *    Achim Kraus (Bosch Software Innovations GmbH) - return null for ACK with mismatching MID
 *    Achim Kraus (Bosch Software Innovations GmbH) - release all tokens except of
 *                                                    starting observe requests
 *    Achim Kraus (Bosch Software Innovations GmbH) - optimize correlation context
 *                                                    processing. issue #311
 *    Achim Kraus (Bosch Software Innovations GmbH) - add check for MID also to responses.
 *                                                    Proactive observe cancellation may cause
 *                                                    errors, if they cancel not completely 
 *                                                    created notifies (before the MID is assigned).
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.Arrays;
import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.observe.ObservationStore;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.CorrelationContextMatcher;

/**
 * A Matcher for CoAP messages transmitted over UDP.
 */
public final class UdpMatcher extends BaseMatcher {

	private static final Logger LOGGER = Logger.getLogger(UdpMatcher.class.getName());

	private final ExchangeObserver exchangeObserver = new ExchangeObserverImpl();
	// TODO: Multicast Exchanges: should not be removed from deduplicator
	private final CorrelationContextMatcher correlationContextMatcher;

	/**
	 * Creates a new matcher for running CoAP over UDP.
	 * 
	 * @param config the configuration to use.
	 * @param notificationListener the callback to invoke for notifications
	 *            received from peers.
	 * @param observationStore the object to use for keeping track of
	 *            observations created by the endpoint this matcher is part of.
	 * @param exchangeStore The store to use for keeping track of message exchanges.
	 * @param matchingStrategy correlation context matcher to relate
	 *            responses with requests
	 * @throws NullPointerException if the configuration, notification listener,
	 *             or the observation store is {@code null}.
	 */
	public UdpMatcher(final NetworkConfig config, final NotificationListener notificationListener,
			final ObservationStore observationStore, final MessageExchangeStore exchangeStore, final CorrelationContextMatcher matchingStrategy) {
		super(config, notificationListener, observationStore, exchangeStore);
		this.correlationContextMatcher = matchingStrategy;
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		if (exchangeStore.registerOutboundRequest(exchange)) {

			exchange.setObserver(exchangeObserver);

			// for observe request.
			if (request.isObserve() && 0 == exchange.getFailedTransmissionCount()) {
				registerObserve(request);
			}

			if (LOGGER.isLoggable(Level.FINER)) {
				LOGGER.log(
						Level.FINER,
						"Tracking open request [MID: {0}, Token: {1}]",
						new Object[] { request.getMID(), request.getTokenString() });
			}
		} else {
			LOGGER.log(Level.WARNING, "Could not register outbound request for tracking");
			// TODO signal failure to register exchange to stack
		}
	}

	@Override
	public void sendResponse(final Exchange exchange, final Response response) {

		// ensure Token is set
		response.setToken(exchange.getCurrentRequest().getToken());

		// If this is a CON notification we now can forget all previous NON notifications
		if (response.getType() == Type.CON || response.getType() == Type.ACK) {
			ObserveRelation relation = exchange.getRelation();
			if (relation != null) {
				removeNotificationsOf(relation, exchange);
			}
		}

		// Insert CON to match ACKs and RSTs to the exchange.
		// Do not insert ACKs and RSTs.
		if (response.getType() == Type.CON) {
			exchangeStore.registerOutboundResponse(exchange);
		} else if (response.getType() == Type.NON) {
			if (response.getOptions().hasObserve()) {
				// this is a NON notification
				// we need to register it so that we can match an RST sent by a peer
				// that wants to cancel the observation
				// these NON notifications will later be removed from the exchange store
				// when ExchangeObserverImpl.completed() is called 
				exchangeStore.registerOutboundResponse(exchange);
			} else {
				// we only need to assign an unused MID but we do not need to register
				// the exchange under the MID since we do not expect/want a reply
				// that we would need to match it against
				exchangeStore.assignMessageId(response);
			}
		}

		// Only CONs and Observe keep the exchange active (CoAP server side)
		if (response.getType() != Type.CON && response.isLast()) {
			exchange.setComplete();
		}
	}

	@Override
	public void sendEmptyMessage(final Exchange exchange, final EmptyMessage message) {

		// ensure Token is set
		message.setToken(new byte[0]);

		if (message.getType() == Type.RST && exchange != null) {
			// We have rejected the request or response
			exchange.setComplete();
		}
	}

	@Override
	public Exchange receiveRequest(final Request request) {
		/*
		 * This request could be
		 *  - Complete origin request => deliver with new exchange
		 *  - One origin block        => deliver with ongoing exchange
		 *  - Complete duplicate request or one duplicate block (because client got no ACK)
		 *      =>
		 * 		if ACK got lost => resend ACK
		 * 		if ACK+response got lost => resend ACK+response
		 * 		if nothing has been sent yet => do nothing
		 * (Retransmission is supposed to be done by the retransm. layer)
		 */

		KeyMID idByMID = KeyMID.fromInboundMessage(request);

		Exchange exchange = new Exchange(request, Origin.REMOTE);
		Exchange previous = exchangeStore.findPrevious(idByMID, exchange);
		if (previous == null) {
			exchange.setObserver(exchangeObserver);
			return exchange;

		} else {
			LOGGER.log(Level.FINER, "Duplicate request: {0}", request);
			request.setDuplicate(true);
			return previous;
		}
	}

	@Override
	public Exchange receiveResponse(final Response response, final CorrelationContext responseContext) {

		/*
		 * This response could be
		 * - The first CON/NCON/ACK+response => deliver
		 * - Retransmitted CON (because client got no ACK)
		 * 		=> resend ACK
		 */

		KeyMID idByMID = KeyMID.fromInboundMessage(response);
		final KeyToken idByToken = KeyToken.fromInboundMessage(response);
		LOGGER.log(Level.FINER, "received response {0}", response);
		Exchange exchange = exchangeStore.get(idByToken);
		boolean isNotify = false; // don't remove MID for notifies. May be already reused.

		if (exchange == null) {
			// we didn't find a message exchange for the token from the response
			// that is scoped to the response's source endpoint address
			// let's try to find an existing observation for the token
			// NOTE this approach is very prone to faked notifications
			// because we do not check that the notification's sender is
			// the same as the receiver of the original observe request
			// TODO: assert that notification's source endpoint is correct
			isNotify = true;
			exchange = matchNotifyResponse(response, responseContext);
		}

		if (exchange == null) {
			// There is no exchange with the given token, nor is there
			// an active observation for that token
			// finally check if the response is a duplicate
			if (response.getType() != Type.ACK) {
				// deduplication is only relevant for CON/NON messages
				Exchange prev = exchangeStore.find(idByMID);
				if (prev != null) {
					LOGGER.log(Level.FINER, "Received response for already completed exchange: {0}", response);
					response.setDuplicate(true);
					return prev;
				}
			} else {
				LOGGER.log(Level.FINER, "Discarding unmatchable piggy-backed response from [{0}:{1}]: {2}",
						new Object[]{response.getSource(), response.getSourcePort(), response});
			}
			// ignore response
			return null;
		} else if (correlationContextMatcher.isResponseRelatedToRequest(exchange.getCorrelationContext(), responseContext)) {

			if (response.getType() == Type.ACK && exchange.getCurrentRequest().getMID() != response.getMID()) {
				// The token matches but not the MID.
				LOGGER.log(Level.WARNING,
						"Possible MID reuse before lifetime end for token [{0}], expected MID {1} but received {2}",
						new Object[] { response.getTokenString(), exchange.getCurrentRequest().getMID(),
								response.getMID() });
				// when nested blockwise request/responses occurs (e.g. caused
				// by retransmission), a old response may stop the
				// retransmission of the current blockwise request. This seems
				// to be a side effect of reusing the token. If the response to
				// this current request is lost, the blockwise transfer times
				// out, because the retransmission is stopped too early.
				// Therefore don't return a exchange when the MID doesn't match.
				// See issue #275
				return null;
			}
			// we have received a Response matching the token of an ongoing Exchange's Request
			// according to the CoAP spec (https://tools.ietf.org/html/rfc7252#section-4.5),
			// message deduplication is relevant for CON and NON messages only

			if ((response.getType() == Type.CON || response.getType() == Type.NON) &&
					exchangeStore.findPrevious(idByMID, exchange) != null) {
				LOGGER.log(Level.FINER, "Received duplicate response for open exchange: {0}", response);
				response.setDuplicate(true);
			} else if (!isNotify) {
				// we have received the expected response for the original request
				idByMID = KeyMID.fromOutboundMessage(exchange.getCurrentRequest());
				if (exchangeStore.remove(idByMID, exchange) != null) {
					LOGGER.log(Level.FINE, "Closed open request [{0}]", idByMID);
				}
			}

			return exchange;
		} else {
			LOGGER.log(Level.INFO, "Ignoring potentially forged response for token {0} with non-matching correlation context", idByToken);
			return null;
		}
	}

	@Override
	public Exchange receiveEmptyMessage(final EmptyMessage message) {

		// an empty ACK or RST always is received as a reply to a message
		// exchange originating locally, i.e. the message will echo an MID
		// that has been created here
		KeyMID idByMID = KeyMID.fromInboundMessage(message);
		Exchange exchange = exchangeStore.remove(idByMID, null);

		if (exchange != null) {
			LOGGER.log(Level.FINE, "Received expected reply for message exchange {0}", idByMID);
		} else {
			LOGGER.log(Level.FINE,
					"Ignoring unmatchable empty message from {0}:{1}: {2}",
					new Object[]{message.getSource(), message.getSourcePort(), message});
		}
		return exchange;
	}

	private void removeNotificationsOf(final ObserveRelation relation, final Exchange exchange) {
		LOGGER.log(Level.FINE, "Removing all remaining NON-notifications of observe relation with {0}",
				relation.getSource());
		for (Iterator<Response> iterator = relation.getNotificationIterator(); iterator.hasNext(); ) {
			Response previous = iterator.next();
			LOGGER.log(Level.FINER, "removing NON notification: {0}", previous);
			// notifications are local MID namespace
			if (previous.hasMID()) {
				KeyMID idByMID = KeyMID.fromOutboundMessage(previous);
				exchangeStore.remove(idByMID, exchange);
			}
			else {
				previous.cancel();
			}
			iterator.remove();
		}
	}

	private class ExchangeObserverImpl implements ExchangeObserver {

		@Override
		public void completed(final Exchange exchange) {

			if (exchange.getOrigin() == Origin.LOCAL) {
				// this endpoint created the Exchange by issuing a request

				Request originRequest = exchange.getCurrentRequest();
				if (!originRequest.hasMID()) {
					// This means that the original request has never been sent at all to the peer,
					// e.g. if the original request contained a payload that required
					// transparent blockwise transfer handled by the BlockwiseLayer.

					// In this case the original request has been (transparently) replaced
					// by the BlockwiseLayer with a sequence of separate request/response message
					// exchanges for transferring the large payload of the request (and possibly also
					// for retrieving the large response). All of these exchanges
					// will already have been completed individually and we are now looking at the original
					// request that has never been sent to the peer. We therefore do not
					// need to try to remove its corresponding exchange from the store.
				} else {
					// in case an empty ACK was lost
					KeyMID idByMID = KeyMID.fromOutboundMessage(originRequest);
					exchangeStore.remove(idByMID, exchange);
				}

				if (originRequest.getToken() == null) {
					// this should not happen because we only register the observer
					// if we have successfully registered the exchange
					LOGGER.log(
							Level.WARNING,
							"exchange observer has been completed on unregistered exchange [peer: {0}:{1}, origin: {2}]",
							new Object[]{ originRequest.getDestination(), originRequest.getDestinationPort(),
									exchange.getOrigin()});
				} else {
					KeyToken idByToken = KeyToken.fromOutboundMessage(originRequest);
					exchangeStore.remove(idByToken, exchange);
					if (!originRequest.isObserve()) {
						exchangeStore.releaseToken(idByToken);
					}
					/* filter calls by completeCurrentRequest */
					if (exchange.isComplete()) {
						/*
						 * keep track of the starting request. Currently only
						 * used with blockwise transfer
						 */
						Request request = exchange.getRequest();
						if (request != originRequest && null != request.getToken()
								&& !Arrays.equals(request.getToken(), originRequest.getToken())) {
							// remove starting request also
							idByToken = KeyToken.fromOutboundMessage(request);
							exchangeStore.remove(idByToken, exchange);
							if (!request.isObserve()) {
								exchangeStore.releaseToken(idByToken);
							}
						}
					}
					LOGGER.log(Level.FINER, "Exchange [{0}, origin: {1}] completed", new Object[]{idByToken, exchange.getOrigin()});
				}

			} else { // Origin.REMOTE
				// this endpoint created the Exchange to respond to a request

				Response response = exchange.getCurrentResponse();

				if (response != null && response.getType() != Type.ACK) {
					// this means that we have sent the response in a separate CON/NON message
					// (not piggy-backed in ACK). The response therefore has a different MID
					// than the original request

					// first remove the entry for the (separate) response's MID
					if (response.hasMID()) {
						KeyMID midKey = KeyMID.fromOutboundMessage(response);
						exchangeStore.remove(midKey, exchange);

						LOGGER.log(Level.FINER, "Exchange [{0}, {1}] completed", new Object[]{midKey, exchange.getOrigin()});
					}
					else {
						// sometime proactive cancel requests and notifies are overlapping
						response.cancel();
					}
				}

				// Remove all remaining NON-notifications if this exchange is an observe relation
				ObserveRelation relation = exchange.getRelation();
				if (relation != null) {
					removeNotificationsOf(relation, exchange);
				}
			}
		}

		@Override
		public void contextEstablished(final Exchange exchange) {
			Request request = exchange.getRequest(); 
			if (request != null && request.isObserve()) {
				observationStore.setContext(request.getToken(), exchange.getCorrelationContext());
			}
		}
	}
}
