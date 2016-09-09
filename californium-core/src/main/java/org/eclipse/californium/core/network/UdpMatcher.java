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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.Iterator;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.Exchange.KeyUri;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.observe.Observation;
import org.eclipse.californium.core.observe.ObservationStore;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.DtlsCorrelationContext;

/**
 * A Matcher for CoAP messages transmitted over UDP.
 */
public final class UdpMatcher extends BaseMatcher {

	private static final Logger LOGGER = Logger.getLogger(UdpMatcher.class.getName());

	private final ExchangeObserver exchangeObserver = new ExchangeObserverImpl();
	// TODO: Multicast Exchanges: should not be removed from deduplicator
	private final boolean useStrictResponseMatching;
	private NotificationListener notificationListener;
	private ObservationStore observationStore;

	/**
	 * Creates a new matcher for running CoAP over UDP.
	 * 
	 * @param config the configuration to use.
	 * @param notificationListener the callback to invoke for notifications received from peers.
	 * @param observationStore the object to use for keeping track of observations created by the endpoint
	 *        this matcher is part of.
	 * @throws NullPointerException if the configuration is {@code null}.
	 */
	public UdpMatcher(final NetworkConfig config, final NotificationListener notificationListener,
			final ObservationStore observationStore) {
		super(config);
		this.notificationListener = notificationListener;
		this.observationStore = observationStore;
		useStrictResponseMatching = config.getBoolean(NetworkConfig.Keys.USE_STRICT_RESPONSE_MATCHING);

		LOGGER.log(Level.CONFIG, "{0} uses {1}={2}",
				new Object[]{getClass().getSimpleName(),
						NetworkConfig.Keys.USE_STRICT_RESPONSE_MATCHING,
						useStrictResponseMatching});
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		exchange.setObserver(exchangeObserver);
		exchangeStore.registerOutboundRequest(exchange);

		// for observe request.
		// We ignore blockwise request, except when this is an early negociation (num and M is set to 0)  
		if (request.getOptions().hasObserve() && request.getOptions().getObserve() == 0 && (!request.getOptions().hasBlock2()
				|| request.getOptions().getBlock2().getNum() == 0 && !request.getOptions().getBlock2().isM())) {
			// add request to the store
			LOGGER.log(Level.FINER, "registering observe request {0}", request);
			observationStore.add(new Observation(request, null));
			// remove it if the request is cancelled, rejected or timedout
			request.addMessageObserver(new MessageObserverAdapter() {
				@Override
				public void onCancel() {
					observationStore.remove(request.getToken());
				}
				@Override
				public void onReject() {
					observationStore.remove(request.getToken());
				}
				@Override
				public void onTimeout() {
					observationStore.remove(request.getToken());
				}
			});
		}

		if (LOGGER.isLoggable(Level.FINER)) {
			LOGGER.log(
					Level.FINER,
					"Tracking open request [MID: {0}, Token: {1}]",
					new Object[] { request.getMID(), request.getTokenString() });
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
				removeNotificationsOf(relation);
			}
		}

		// Blockwise transfers are identified by URI and remote endpoint
		if (response.getOptions().hasBlock2()) {
			Request request = exchange.getCurrentRequest();
			KeyUri idByUri = KeyUri.fromInboundRequest(request);
			// Observe notifications only send the first block, hence do not store them as ongoing
			if (exchange.getResponseBlockStatus() != null && !response.getOptions().hasObserve()) {
				// Remember ongoing blockwise GET requests
				if (exchangeStore.registerBlockwiseExchange(idByUri, exchange) == null) {
					LOGGER.log(Level.FINE, "Ongoing Block2 started late, storing {0} for {1}",
							new Object[]{idByUri, request});
				} else {
					LOGGER.log(Level.FINE, "Ongoing Block2 continued, storing {0} for {1}",
							new Object[]{idByUri, request});
				}
			} else {
				LOGGER.log(Level.FINE, "Ongoing Block2 completed, cleaning up {0} for {1}",
						new Object[] { idByUri, request });
				exchangeStore.remove(idByUri);
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
				//the exchange under the MID since we do not expect/want a reply
				// that we would need to match it against
				exchangeStore.assignMessageId(response);
			}
		}

		// Only CONs and Observe keep the exchange active
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

		/*
		 * The differentiation between the case where there is a Block1 or
		 * Block2 option and the case where there is none has the advantage that
		 * all exchanges that do not need blockwise transfer have simpler and
		 * faster code than exchanges with blockwise transfer.
		 */
		if (!request.getOptions().hasBlock1() && !request.getOptions().hasBlock2()) {

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

		} else {

			KeyUri idByUri = KeyUri.fromInboundRequest(request);
			LOGGER.log(Level.FINE, "Looking up ongoing exchange for {0}", idByUri);

			Exchange ongoing = exchangeStore.get(idByUri);
			if (ongoing != null) {

				Exchange prev = exchangeStore.findPrevious(idByMID, ongoing);
				if (prev != null) {
					LOGGER.log(Level.FINER, "Duplicate ongoing request: {0}", request);
					request.setDuplicate(true);
				} else {
					// this request is part of an ongoing blockwise transfer
					// we can (i.e. must) clean up the previous response
					// check for null, in case no response was created (e.g., because the resource handler crashed...)
					if (ongoing.getCurrentResponse() != null && ongoing.getCurrentResponse().getType() != Type.ACK
							&& !ongoing.getCurrentResponse().getOptions().hasObserve()) {
						// TODO is this still necessary in 2.0.x where we complete every exchange
						idByMID = KeyMID.fromOutboundMessage(ongoing.getCurrentResponse());
						LOGGER.log(Level.FINE, "Ongoing exchange got new request, cleaning up {0}", idByMID);
						exchangeStore.remove(idByMID);
					}
				}
				return ongoing;

			} else {
				// We have no ongoing exchange for that request block.
				/*
				 * Note the difficulty of the following code: The first message
				 * of a blockwise transfer might arrive twice due to a
				 * retransmission. The new Exchange must be inserted in both the
				 * hash map 'ongoing' and the deduplicator. They must agree on
				 * which exchange they store!
				 */
				
				Exchange exchange = new Exchange(request, Origin.REMOTE);
				Exchange previous = exchangeStore.findPrevious(idByMID, exchange);
				if (previous == null) {
					LOGGER.log(Level.FINER, "New ongoing request, storing {0} for {1}", new Object[]{idByUri, request});
					exchange.setObserver(exchangeObserver);
					exchangeStore.registerBlockwiseExchange(idByUri, exchange);
					return exchange;
				} else {
					LOGGER.log(Level.FINER, "Duplicate initial request: {0}", request);
					request.setDuplicate(true);
					return previous;
				}
			} // if ongoing
		} // if blockwise
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
		KeyToken idByToken = KeyToken.fromInboundMessage(response);
		LOGGER.log(Level.FINER, "received response {0}", response);
		Exchange exchange = exchangeStore.get(idByToken);

		if (exchange == null && observationStore != null ) {
			// we didn't find a message exchange for the token from the response
			// that is scoped to the response's source endpoint address
			// let's try to find an existing observation for the token
			// NOTE this approach is very prone to faked notifications
			// because we do not check that the notification's sender is
			// the same as the receiver of the original observe request
			// TODO: assert that notification's source endpoint is correct
			final Observation obs = observationStore.get(response.getToken());
			if (obs != null) {
				// there is an observation for the token from the response
				// re-create a corresponding Exchange object for it so
				// that the "upper" layers can correctly process the notification response
				final Request request = obs.getRequest();
				request.setDestination(response.getSource());
				request.setDestinationPort(response.getSourcePort());
				exchange = new Exchange(request, Origin.LOCAL, obs.getContext());
				exchange.setRequest(request);
				exchange.setObserver(exchangeObserver);
				LOGGER.log(Level.FINER, "re-created exchange from original observe request: {0}", request);
				request.addMessageObserver(new MessageObserverAdapter() {

					@Override
					public void onTimeout() {
						observationStore.remove(request.getToken());
					}

					@Override
					public void onResponse(final Response resp) {
						notificationListener.onNotification(request, resp);
					}

					@Override
					public void onReject() {
						observationStore.remove(request.getToken());
					}

					@Override
					public void onCancel() {
						observationStore.remove(request.getToken());
					}
				});
			}
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
		} else if (isResponseRelatedToRequest(exchange, responseContext)) {

			// we have received a Response matching the token of an ongoing Exchange's Request
			// according to the CoAP spec (https://tools.ietf.org/html/rfc7252#section-4.5),
			// message deduplication is relevant for CON and NON messages only

			if ((response.getType() == Type.CON || response.getType() == Type.NON) &&
					exchangeStore.findPrevious(idByMID, exchange) != null) {
				LOGGER.log(Level.FINER, "Received duplicate response for open exchange: {0}", response);
				response.setDuplicate(true);
			} else {
				// we have received the expected response for the original request
				idByMID = KeyMID.fromOutboundMessage(exchange.getCurrentRequest());
				exchangeStore.remove(idByMID);
				LOGGER.log(Level.FINE, "Closed open request [{0}]", idByMID);
			}

			if (response.getType() == Type.ACK && exchange.getCurrentRequest().getMID() != response.getMID()) {
				// The token matches but not the MID.
				LOGGER.log(Level.WARNING,
						"Possible MID reuse before lifetime end for token [{0}], expected MID {1} but received {2}",
						new Object[]{response.getTokenString(), exchange.getCurrentRequest().getMID(), response.getMID()});
			}

			return exchange;
		} else {
			LOGGER.log(Level.INFO, "Ignoring potentially forged response for token {0} with non-matching correlation context", idByToken);
			return null;
		}
	}

	private boolean isResponseRelatedToRequest(final Exchange exchange, final CorrelationContext responseContext) {
		if (exchange.getCorrelationContext() == null) {
			// no correlation information available for request, thus any
			// additional correlation information available in the response is ignored
			return true;
		} else if (exchange.getCorrelationContext().get(DtlsCorrelationContext.KEY_SESSION_ID) != null) {
			// original request has been sent via a DTLS protected transport
			// check if the response has been received in the same DTLS session
			if (useStrictResponseMatching) {
				return isResponseStrictlyRelatedToDtlsRequest(exchange.getCorrelationContext(), responseContext);
			} else {
				return isResponseRelatedToDtlsRequest(exchange.getCorrelationContext(), responseContext);
			}
		} else {
			// compare message context used for sending original request to context
			// the response has been received in
			return exchange.getCorrelationContext().equals(responseContext);
		}
	}

	private boolean isResponseRelatedToDtlsRequest(final CorrelationContext requestContext, final CorrelationContext responseContext) {
		if (responseContext == null) {
			return false;
		} else {
			return requestContext.get(DtlsCorrelationContext.KEY_SESSION_ID)
					.equals(responseContext.get(DtlsCorrelationContext.KEY_SESSION_ID))
					&& requestContext.get(DtlsCorrelationContext.KEY_CIPHER)
							.equals(responseContext.get(DtlsCorrelationContext.KEY_CIPHER));
		}
	}

	private boolean isResponseStrictlyRelatedToDtlsRequest(final CorrelationContext requestContext, final CorrelationContext responseContext) {
		if (responseContext == null) {
			return false;
		} else {
			return requestContext.get(DtlsCorrelationContext.KEY_SESSION_ID)
					.equals(responseContext.get(DtlsCorrelationContext.KEY_SESSION_ID))
					&& requestContext.get(DtlsCorrelationContext.KEY_EPOCH)
							.equals(responseContext.get(DtlsCorrelationContext.KEY_EPOCH))
					&& requestContext.get(DtlsCorrelationContext.KEY_CIPHER)
							.equals(responseContext.get(DtlsCorrelationContext.KEY_CIPHER));
		}
	}

	@Override
	public Exchange receiveEmptyMessage(final EmptyMessage message) {

		// an empty ACK or RST always is received as a reply to a message
		// exchange originating locally, i.e. the message will echo an MID
		// that has been created here
		KeyMID idByMID = KeyMID.fromInboundMessage(message);
		Exchange exchange = exchangeStore.remove(idByMID);

		if (exchange != null) {
			LOGGER.log(Level.FINE, "Received expected reply for message exchange {0}", idByMID);
		} else {
			LOGGER.log(Level.FINE,
					"Ignoring unmatchable empty message from {0}:{1}: {2}",
					new Object[]{message.getSource(), message.getSourcePort(), message});
		}
		return exchange;
	}

	private void removeNotificationsOf(final ObserveRelation relation) {
		LOGGER.log(Level.FINE, "Removing all remaining NON-notifications of observe relation with {0}",
				relation.getSource());
		for (Iterator<Response> iterator = relation.getNotificationIterator(); iterator.hasNext(); ) {
			Response previous = iterator.next();
			// notifications are local MID namespace
			KeyMID idByMID = KeyMID.fromOutboundMessage(previous);
			exchangeStore.remove(idByMID);
			iterator.remove();
		}
	}

	private class ExchangeObserverImpl implements ExchangeObserver {

		@Override
		public void completed(final Exchange exchange) {

			/*
			 * Logging in this method leads to significant performance loss.
			 * Uncomment logging code only for debugging purposes.
			 */

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
					KeyMID idByMID = KeyMID.fromOutboundMessage(exchange.getCurrentRequest());
					exchangeStore.remove(idByMID);
				}
				KeyToken idByToken = KeyToken.fromOutboundMessage(originRequest);
				exchangeStore.remove(idByToken);
				LOGGER.log(Level.FINER, "Exchange [{0}, {1}] completed", new Object[]{idByToken, exchange.getOrigin()});

			} else { // Origin.REMOTE
				// this endpoint created the Exchange to respond to a request

				Response response = exchange.getCurrentResponse();
				Request request = exchange.getCurrentRequest();

				if (response != null && response.getType() != Type.ACK) {
					// this means that we have sent the response in a separate CON/NON message
					// (not piggy-backed in ACK). The response therefore has a different MID
					// than the original request

					// first remove the entry for the (separate) response's MID
					KeyMID midKey = KeyMID.fromOutboundMessage(response);
					exchangeStore.remove(midKey);

					LOGGER.log(Level.FINER, "Exchange [{0}, {1}] completed", new Object[]{midKey, exchange.getOrigin()});
				}

				if (request != null && (request.getOptions().hasBlock1() || response.getOptions().hasBlock2())) {
					KeyUri uriKey = new KeyUri(request.getURI(), request.getSource().getAddress(),
							request.getSourcePort());
					LOGGER.log(Level.FINE, "Blockwise exchange with remote peer {0} completed, cleaning up ", uriKey);
					exchangeStore.remove(uriKey);
				}

				// Remove all remaining NON-notifications if this exchange is an observe relation
				ObserveRelation relation = exchange.getRelation();
				if (relation != null) {
					removeNotificationsOf(relation);
				}
			}
		}

		@Override
		public void contextEstablished(Exchange exchange) {
			if (exchange.getRequest() != null)
				observationStore.setContext(exchange.getRequest().getToken(), exchange.getCorrelationContext());
			KeyToken token = KeyToken.fromOutboundMessage(exchange.getCurrentRequest());
			exchangeStore.setContext(token, exchange.getCorrelationContext());
		}
	}

	/**
	 * Cancels all pending blockwise requests that have been induced by a notification
	 * we have received indicating a blockwise transfer of the resource.
	 * 
	 * @param token the token of the observation.
	 */
	@Override
	public void cancelObserve(final byte[] token) {
		// we do not know the destination endpoint the requests have been sent to
		// therefore we need to find them by token only
		for (Exchange exchange : exchangeStore.findByToken(token)) {
			exchange.getRequest().cancel();
		}
		observationStore.remove(token);
	}
}
