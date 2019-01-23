/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace parameter EndpointContext 
 *                                                    by EndpointContext of response.
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - adjust to use Token
 *                                                    store observation before exchange
 *                                                    to create global token
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 *    Achim Kraus (Bosch Software Innovations GmbH) - add token generator
 *    Achim Kraus (Bosch Software Innovations GmbH) - change ExchangeObserver
 *                                                    to RemoveHandler
 *                                                    remove "is last", not longer meaningful
 *    Achim Kraus (Bosch Software Innovations GmbH) - assign mid before register observation
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove exchange on ACK/RST only after
 *                                                    context matching
 *    Achim Kraus (Bosch Software Innovations GmbH) - add support for multicast
 *    Achim Kraus (Bosch Software Innovations GmbH) - deduplication base on the ip-address
 *                                                    and MID may fail when requests
 *                                                    addresses are changing
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.CoAP.Type;

import java.util.concurrent.Executor;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.observe.ObservationStore;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextMatcher;

/**
 * A Matcher for CoAP messages transmitted over UDP.
 */
public final class UdpMatcher extends BaseMatcher {

	private static final Logger LOGGER = LoggerFactory.getLogger(UdpMatcher.class.getName());

	// TODO: Multicast Exchanges: should not be removed from deduplicator
	private final RemoveHandler exchangeRemoveHandler = new RemoveHandlerImpl();
	private final EndpointContextMatcher endpointContextMatcher;

	/**
	 * Creates a new matcher for running CoAP over UDP.
	 * 
	 * @param config the configuration to use.
	 * @param notificationListener the callback to invoke for notifications
	 *            received from peers.
	 * @param tokenGenerator token generator to create tokens for observations
	 *            created by the endpoint this matcher is part of.
	 * @param observationStore the object to use for keeping track of
	 *            observations created by the endpoint this matcher is part of.
	 * @param exchangeStore The store to use for keeping track of message
	 *            exchanges.
	 * @param executor executor to be used for exchanges.
	 * @param matchingStrategy endpoint context matcher to relate responses with
	 *            requests
	 * @throws NullPointerException if one of the parameters is {@code null}.
	 */
	public UdpMatcher(NetworkConfig config, NotificationListener notificationListener, TokenGenerator tokenGenerator,
			ObservationStore observationStore, MessageExchangeStore exchangeStore, Executor executor,
			EndpointContextMatcher matchingStrategy) {
		super(config, notificationListener, tokenGenerator, observationStore, exchangeStore, executor);
		this.endpointContextMatcher = matchingStrategy;
	}

	@Override
	public void sendRequest(final Exchange exchange) {

		// for observe request.
		Request request = exchange.getCurrentRequest();
		if (request.isObserve() && 0 == exchange.getFailedTransmissionCount()) {
			if (exchangeStore.assignMessageId(request) != Message.NONE) {
				registerObserve(request);
			} else {
				LOGGER.warn("message IDs exhausted, could not register outbound observe request for tracking");
				request.setSendError(new IllegalStateException("automatic message IDs exhausted"));
				return;
			}
		}

		try {
			if (exchangeStore.registerOutboundRequest(exchange)) {
				exchange.setRemoveHandler(exchangeRemoveHandler);
				LOGGER.debug("tracking open request [MID: {}, Token: {}]", request.getMID(), request.getToken());
			} else {
				LOGGER.warn("message IDs exhausted, could not register outbound request for tracking");
				request.setSendError(new IllegalStateException("automatic message IDs exhausted"));
			}
		} catch (IllegalArgumentException ex) {
			request.setSendError(ex);
		}
	}

	@Override
	public void sendResponse(final Exchange exchange) {

		boolean ready = true;
		Response response = exchange.getCurrentResponse();
		// ensure Token is set
		response.setToken(exchange.getCurrentRequest().getToken());

		// Insert CON to match ACKs and RSTs to the exchange.
		// Do not insert ACKs and RSTs.
		if (response.getType() == Type.CON) {
			// If this is a CON notification we now can forget
			// all previous NON notifications
			exchange.removeNotifications();
			exchangeStore.registerOutboundResponse(exchange);
			ready = false;
		} else if (response.getType() == Type.NON) {
			if (response.isNotification()) {
				// this is a NON notification
				// we need to register it so that we can match an RST sent
				// by a peer that wants to cancel the observation
				// these NON notifications will later be removed from the
				// exchange store when Exchange.setComplete() is called
				exchangeStore.registerOutboundResponse(exchange);
				ready = false;
			} else {
				// we only need to assign an unused MID but we do not need to
				// register the exchange under the MID since we do not
				// expect/want a reply that we would need to match it against
				exchangeStore.assignMessageId(response);
			}
		}

		// Only CONs and Observe keep the exchange active (CoAP server side)
		if (ready) {
			exchange.setComplete();
		}
	}

	@Override
	public void sendEmptyMessage(final Exchange exchange, final EmptyMessage message) {

		// ensure Token is set
		message.setToken(Token.EMPTY);

		if (message.getType() == Type.RST && exchange != null) {
			// We have rejected the request or response
			exchange.setComplete();
		}
	}

	@Override
	public void receiveRequest(final Request request, final EndpointReceiver receiver) {
		// This request could be
		//  - Complete origin request => deliver with new exchange
		//  - One origin block        => deliver with ongoing exchange
		//  - Complete duplicate request or one duplicate block (because client got no ACK)
		//      =>
		//      if ACK got lost => resend ACK
		//      if ACK+response got lost => resend ACK+response
		//      if nothing has been sent yet => do nothing
		// (Retransmission is supposed to be done by the retransm. layer)

		final KeyMID idByMID = KeyMID.fromInboundMessage(request);
		final Exchange exchange = new Exchange(request, Origin.REMOTE, executor);
		final Exchange previous = exchangeStore.findPrevious(idByMID, exchange);
		boolean duplicate = previous != null;

		if (duplicate) {
			// assuming addresses changing, request could not only be deduplicated by their address and mid.
			EndpointContext sourceContext = request.getSourceContext();
			Request previousRequest = previous.getRequest();
			EndpointContext previousSourceContext = previousRequest.getSourceContext();
			// the previous response would be send with its previous context using 
			// the current request context as connection context
			duplicate = endpointContextMatcher.isToBeSent(previousSourceContext, sourceContext);
			if (!duplicate) {
				// the new context doesn't match the previous.
				exchangeStore.remove(idByMID, previous);
				if (exchangeStore.findPrevious(idByMID, exchange) != null) {
					LOGGER.warn("new request could not be registered!");
				}
			}
		}

		if (duplicate) {
			LOGGER.trace("duplicate request: {}", request);
			request.setDuplicate(true);
			previous.execute(new Runnable() {

				@Override
				public void run() {
					try {
						receiver.receiveRequest(previous, request);
					} catch (RuntimeException ex) {
						LOGGER.warn("error receiving request {} again!", request, ex);
						receiver.reject(request);
					}
				}
			});
		} else {
			exchange.setRemoveHandler(exchangeRemoveHandler);
			exchange.execute(new Runnable() {

				@Override
				public void run() {
					try {
						receiver.receiveRequest(exchange, request);
					} catch (RuntimeException ex) {
						LOGGER.warn("error receiving request {}", request, ex);
						receiver.reject(request);
					}
				}
			});
		}
	}

	@Override
	public void receiveResponse(final Response response, final EndpointReceiver receiver) {

		// This response could be
		// - The first CON/NCON/ACK+response => deliver
		// - Retransmitted CON (because client got no ACK)
		// => resend ACK

		final Token idByToken = response.getToken();
		LOGGER.trace("received response {}", response);
		Exchange tempExchange = exchangeStore.get(idByToken);

		if (tempExchange == null) {
			// we didn't find a message exchange for the token from the response
			// let's try to find an existing observation for the token
			tempExchange = matchNotifyResponse(response);
		}

		if (tempExchange == null) {
			// There is no exchange with the given token,
			// nor is there an active observation for that token.
			// finally check if the response is a duplicate
			if (response.getType() != Type.ACK) {
				// deduplication is only relevant for CON/NON messages
				KeyMID idByMID = KeyMID.fromInboundMessage(response);
				final Exchange prev = exchangeStore.find(idByMID);
				if (prev != null) {
					prev.execute(new Runnable() {

						@Override
						public void run() {

							if (prev.getCurrentRequest().isMulticast()) {
								LOGGER.debug("Ignore delayed response {} to multicast request {}", response,
										prev.getCurrentRequest().getDestinationContext().getPeerAddress());
								return;
							}

							try {
								if (endpointContextMatcher.isResponseRelatedToRequest(prev.getEndpointContext(),
										response.getSourceContext())) {
									LOGGER.trace("received response for already completed {}: {}", prev, response);
									response.setDuplicate(true);
									receiver.receiveResponse(prev, response);
									return;
								}
							} catch (RuntimeException ex) {
								LOGGER.warn("error receiving response {} for {}", response, prev, ex);
							}
							reject(response, receiver);
						}
					});
				} else {
					reject(response, receiver);
				}
			} else {
				LOGGER.trace("discarding unmatchable piggy-backed response from [{}]: {}", response.getSourceContext(),
						response);
			}
			return;
		}

		final Exchange exchange = tempExchange;
		exchange.execute(new Runnable() {

			@Override
			public void run() {
				boolean checkResponseToken = !exchange.isNotification() || exchange.getRequest() != exchange.getCurrentRequest();
				if (checkResponseToken && exchangeStore.get(idByToken) != exchange) {
					if (running) {
						LOGGER.debug("ignoring response {}, exchange not longer matching!", response);
					}
					return;
				}

				EndpointContext context = exchange.getEndpointContext();
				Request currentRequest = exchange.getCurrentRequest();
				int requestMid = currentRequest.getMID();
				if (context == null) {
					LOGGER.debug("ignoring response {}, request pending to sent!", response);
					return;
				}

				try {
					if (endpointContextMatcher.isResponseRelatedToRequest(context, response.getSourceContext())) {
						// As per RFC 7252, section 8.2:
						// When matching a response to a multicast request, only the token MUST
						// match; the source endpoint of the response does not need to (and will
						// not) be the same as the destination endpoint of the original request.
						if (currentRequest.isMulticast()) {
							// do some check, e.g. NON ...
							// this avoids flooding of ACK messages to multicast groups
							if (response.getType() != Type.NON) {
								LOGGER.debug(
										"ignoring response of type {} for multicast request with token [{}], from {}",
										response.getType(), response.getTokenString(), response.getSourceContext().getPeerAddress());
								return;
							}
						} else if (response.getType() == Type.ACK && requestMid != response.getMID()) {
							// The token matches but not the MID.
							LOGGER.debug("ignoring ACK, possible MID reuse before lifetime end for token {}, expected MID {} but received {}",
									response.getTokenString(), requestMid, response.getMID());
							// when nested blockwise request/responses occurs (e.g.
							// caused by retransmission), a old response may stop the
							// retransmission of the current blockwise request. This
							// seems to be a side effect of reusing the token. If the
							// response to this current request is lost, the blockwise
							// transfer times out, because the retransmission is stopped
							// too early. Therefore don't return a exchange when the MID
							// doesn't match.
							// See issue #275
							return;
						}
						// we have received a Response matching the token of an ongoing
						// Exchange's Request according to the CoAP spec
						// (https://tools.ietf.org/html/rfc7252#section-4.5),
						// deduplication is relevant only for CON and NON messages
						KeyMID idByMID = KeyMID.fromInboundMessage(response);
						if ((response.getType() == Type.CON || response.getType() == Type.NON)
								&& exchangeStore.findPrevious(idByMID, exchange) != null) {
							LOGGER.trace("received duplicate response for open {}: {}", exchange, response);
							response.setDuplicate(true);
						} else if (!exchange.isNotification() && !currentRequest.isMulticast()) {
							if (response.isNotification() && response.getType() != Type.ACK
									&& currentRequest.isObserveCancel()) {
								// overlapping notification for observation cancel request
								LOGGER.debug("ignoring notify for pending cancel {}!", response);
								return;
							}
							// we have received the expected response for the
							// original request
							idByMID = KeyMID.fromOutboundMessage(currentRequest);
							if (exchangeStore.remove(idByMID, exchange) != null) {
								LOGGER.debug("closed open request [{}]", idByMID);
							}
						}
						receiver.receiveResponse(exchange, response);
						return;
					} else {
						LOGGER.debug("ignoring potentially forged response for token {} with non-matching endpoint context",
								idByToken);
					}
				} catch (RuntimeException ex) {
					LOGGER.warn("error receiving response {} for {}", response, exchange, ex);
				}
				reject(response, receiver);
			}
		});
	}

	@Override
	public void receiveEmptyMessage(final EmptyMessage message, final EndpointReceiver receiver) {

		// an empty ACK or RST always is received as a reply to a message
		// exchange originating locally, i.e. the message will echo an MID
		// that has been created here
		final KeyMID idByMID = KeyMID.fromInboundMessage(message);
		final Exchange exchange = exchangeStore.get(idByMID);

		if (exchange == null) {
			LOGGER.debug("ignoring unmatchable empty message from {}: {}", message.getSourceContext(), message);
			return;
		}

		exchange.execute(new Runnable() {

			@Override
			public void run() {
				if (exchange.getCurrentRequest().isMulticast()) {
					LOGGER.debug("ignoring {} message for multicast request {}", message.getType(), idByMID);
					return;
				}
				if (exchangeStore.get(idByMID) != exchange) {
					if (running) {
						LOGGER.debug("ignoring ack/rst {}, not longer matching!", message);
					}
					return;
				}
				try {
					if (endpointContextMatcher.isResponseRelatedToRequest(exchange.getEndpointContext(),
							message.getSourceContext())) {
						exchangeStore.remove(idByMID, exchange);
						LOGGER.debug("received expected reply for message {}", idByMID);
						receiver.receiveEmptyMessage(exchange, message);
					} else {
						LOGGER.debug(
								"ignoring potentially forged reply for message {} with non-matching endpoint context",
								idByMID);
					}
				} catch (RuntimeException ex) {
					LOGGER.warn("error receiving empty message {} for {}", message, exchange, ex);
				}
			}
		});
	}

	private void reject(final Response response, final EndpointReceiver receiver) {

		if (response.getType() != Type.ACK && response.hasMID()) {
			// reject only messages with MID, ignore for TCP
			LOGGER.debug("rejecting response from {}", response.getSourceContext());
			receiver.reject(response);
		}
	}

	private class RemoveHandlerImpl implements RemoveHandler {

		@Override
		public void remove(Exchange exchange, Token token, KeyMID key) {
			if (token != null) {
				exchangeStore.remove(token, exchange);
			}
			if (key != null) {
				exchangeStore.remove(key, exchange);
			}
		}
	}
}
