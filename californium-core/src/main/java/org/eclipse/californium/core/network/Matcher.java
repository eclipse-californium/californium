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
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.Exchange.KeyUri;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.deduplication.Deduplicator;
import org.eclipse.californium.core.network.deduplication.DeduplicatorFactory;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.elements.CorrelationContext;
import org.eclipse.californium.elements.DtlsCorrelationContext;

public class Matcher {

	private static final Logger LOGGER = Logger.getLogger(Matcher.class.getCanonicalName());

	private final ConcurrentHashMap<KeyMID, Exchange> exchangesByMID; // for all
	private final ConcurrentHashMap<KeyToken, Exchange> exchangesByToken; // for outgoing
	private final ConcurrentHashMap<KeyUri, Exchange> ongoingExchanges; // for blockwise
	private final ExchangeObserver exchangeObserver = new ExchangeObserverImpl();
	/* managing the MID per endpoint requires remote endpoint management */
	private final AtomicInteger currendMID;
	// TODO: Multicast Exchanges: should not be removed from deduplicator
	private final Deduplicator deduplicator;
	// Idea: Only store acks/rsts and not the whole exchange. Responses should be sent CON.

	private final boolean useStrictResponseMatching;
	/* limit the token size to save bytes in closed environments */
	private final int tokenSizeLimit;
	/* Health status output */
	private final Level healthStatusLevel;
	private final int healthStatusInterval; // seconds

	private boolean started;

	/* the executor, by default the one of the protocol stage */
	private ScheduledExecutorService executor;

	public Matcher(final NetworkConfig config) {
		this.exchangesByMID = new ConcurrentHashMap<>();
		this.exchangesByToken = new ConcurrentHashMap<>();
		this.ongoingExchanges = new ConcurrentHashMap<>();

		DeduplicatorFactory factory = DeduplicatorFactory.getDeduplicatorFactory();
		this.deduplicator = factory.createDeduplicator(config);

		tokenSizeLimit = config.getInt(NetworkConfig.Keys.TOKEN_SIZE_LIMIT);
		useStrictResponseMatching = config.getBoolean(NetworkConfig.Keys.USE_STRICT_RESPONSE_MATCHING);
		boolean randomMID = config.getBoolean(NetworkConfig.Keys.USE_RANDOM_MID_START);
		if (randomMID) {
			currendMID = new AtomicInteger(new Random().nextInt(1<<16));
		} else {
			currendMID = new AtomicInteger(0);
		}

		if (LOGGER.isLoggable(Level.CONFIG)) {
			String msg = new StringBuilder("Matcher uses ")
					.append(NetworkConfig.Keys.USE_RANDOM_MID_START).append("=").append(randomMID).append(", ")
					.append(NetworkConfig.Keys.TOKEN_SIZE_LIMIT).append("=").append(tokenSizeLimit).append(" and ")
					.append(NetworkConfig.Keys.USE_STRICT_RESPONSE_MATCHING).append("=").append(useStrictResponseMatching)
					.toString();
			LOGGER.config(msg);
		}

		healthStatusLevel = Level.parse(config.getString(NetworkConfig.Keys.HEALTH_STATUS_PRINT_LEVEL));
		healthStatusInterval = config.getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL);
	}

	public synchronized void start() {
		if (started) {
			return;
		} else if (executor == null) {
			throw new IllegalStateException("Matcher has no executor to schedule exchange removal");
		} else {
			started = true;
			deduplicator.start();
	
			// this is a useful health metric that could later be exported to some kind of monitoring interface
			if (LOGGER.isLoggable(healthStatusLevel)) {
				executor.scheduleAtFixedRate(new Runnable() {
					@Override
					public void run() {
						LOGGER.log(
							healthStatusLevel,
							"Matcher state: {0} exchangesByMID, {1} exchangesByToken, {2} ongoingExchanges",
							new Object[]{exchangesByMID.size(), exchangesByToken.size(), ongoingExchanges.size()});
					}
				}, healthStatusInterval, healthStatusInterval, TimeUnit.SECONDS);
			}
		}
	}

	public synchronized void stop() {
		if (!started) {
			return;
		} else {
			started = false;
			deduplicator.stop();
			clear();
		}
	}

	public synchronized void setExecutor(final ScheduledExecutorService executor) {
		deduplicator.setExecutor(executor);
		this.executor = executor;
		// health status runnable is not migrated at the moment
	}

	public void sendRequest(Exchange exchange, Request request) {

		// ensure MID is set
		if (request.getMID() == Message.NONE) {
			request.setMID(currendMID.getAndIncrement()%(1<<16)); // wrap at 2^16
		}
		// request MID is from the local namespace -- use blank address
		KeyMID idByMID = new KeyMID(request.getMID());

		// ensure Token is set
		KeyToken idByToken;
		if (request.getToken() == null) {
			idByToken = createUnusedToken();
			request.setToken(idByToken.token);
		} else {
			idByToken = new KeyToken(request.getToken());
			// ongoing requests may reuse token
			if (!(exchange.getFailedTransmissionCount()>0 || request.getOptions().hasBlock1() || request.getOptions().hasBlock2() || request.getOptions().hasObserve()) && exchangesByToken.get(idByToken) != null) {
				LOGGER.log(Level.WARNING, "Manual token overrides existing open request: {0}", idByToken);
			}
		}

		exchange.setObserver(exchangeObserver);
		LOGGER.log(Level.FINE, "Tracking open request using {0}, {1}", new Object[]{idByMID, idByToken});

		exchangesByMID.put(idByMID, exchange);
		exchangesByToken.put(idByToken, exchange);
	}

	public void sendResponse(Exchange exchange, Response response) {

		// ensure MID is set
		if (response.getMID() == Message.NONE) {
			response.setMID(currendMID.getAndIncrement()%(1<<16));
		}

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
			KeyUri idByUri = new KeyUri(request.getURI(), response.getDestination().getAddress(), response.getDestinationPort());
			// Observe notifications only send the first block, hence do not store them as ongoing
			if (exchange.getResponseBlockStatus() != null && !response.getOptions().hasObserve()) {
				// Remember ongoing blockwise GET requests
				if (ongoingExchanges.put(idByUri, exchange) == null) {
					LOGGER.log(Level.FINE, "Ongoing Block2 started late, storing {0} for {1}",
							new Object[]{idByUri, request});
				} else {
					LOGGER.log(Level.FINE, "Ongoing Block2 continued, storing {0} for {1}",
							new Object[]{idByUri, request});
				}
			} else {
				LOGGER.log(Level.FINE, "Ongoing Block2 completed, cleaning up {0} for {1}",
						new Object[]{idByUri, request});
				ongoingExchanges.remove(idByUri);
			}
		}

		// Insert CON and NON to match ACKs and RSTs to the exchange.
		// Do not insert ACKs and RSTs.
		if (response.getType() == Type.CON || response.getType() == Type.NON) {
			KeyMID idByMID = new KeyMID(response.getMID());
			exchangesByMID.put(idByMID, exchange);
		}

		// Only CONs and Observe keep the exchange active
		if (response.getType() != Type.CON && response.isLast()) {
			exchange.setComplete();
		}
	}

	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {

		// ensure Token is set
		message.setToken(new byte[0]);

		if (message.getType() == Type.RST && exchange != null) {
			// We have rejected the request or response
			exchange.setComplete();
		}
	}

	public Exchange receiveRequest(Request request) {
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
			Exchange previous = deduplicator.findPrevious(idByMID, exchange);
			if (previous == null) {
				exchange.setObserver(exchangeObserver);
				return exchange;

			} else {
				LOGGER.log(Level.FINER, "Duplicate request: {0}", request);
				request.setDuplicate(true);
				return previous;
			}

		} else {

			KeyUri idByUri = new KeyUri(request.getURI(), request.getSource().getAddress(), request.getSourcePort());
			LOGGER.log(Level.FINE, "Looking up ongoing exchange for {0}", idByUri);

			Exchange ongoing = ongoingExchanges.get(idByUri);
			if (ongoing != null) {

				Exchange prev = deduplicator.findPrevious(idByMID, ongoing);
				if (prev != null) {
					LOGGER.log(Level.FINER, "Duplicate ongoing request: {0}", request);
					request.setDuplicate(true);
				} else {
					// the exchange is continuing, we can (i.e., must) clean up the previous response
					// check for null, in case no response was created (e.g., because the resource handler crashed...)
					if (ongoing.getCurrentResponse() != null && ongoing.getCurrentResponse().getType() != Type.ACK && !ongoing.getCurrentResponse().getOptions().hasObserve()) {
						idByMID = new KeyMID(ongoing.getCurrentResponse().getMID());
						LOGGER.log(Level.FINE, "Ongoing exchange got new request, cleaning up {0}", idByMID);
						exchangesByMID.remove(idByMID);
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
				Exchange previous = deduplicator.findPrevious(idByMID, exchange);
				if (previous == null) {
					LOGGER.log(Level.FINER, "New ongoing request, storing {0} for {1}", new Object[]{idByUri, request});
					exchange.setObserver(exchangeObserver);
					ongoingExchanges.put(idByUri, exchange);
					return exchange;
				} else {
					LOGGER.log(Level.FINER, "Duplicate initial request: {0}", request);
					request.setDuplicate(true);
					return previous;
				}
			} // if ongoing
		} // if blockwise
	}

	public Exchange receiveResponse(final Response response, final CorrelationContext responseContext) {

		/*
		 * This response could be
		 * - The first CON/NCON/ACK+response => deliver
		 * - Retransmitted CON (because client got no ACK)
		 * 		=> resend ACK
		 */

		KeyMID idByMID;
		if (response.getType() == Type.ACK) {
			// own namespace
			idByMID = new KeyMID(response.getMID());
		} else {
			// remote namespace
			idByMID = KeyMID.fromInboundMessage(response);
		}

		KeyToken idByToken = new KeyToken(response.getToken());

		Exchange exchange = exchangesByToken.get(idByToken);

		if (exchange == null) {
			// There is no exchange with the given token.
			if (response.getType() != Type.ACK) {
				// only act upon separate (non piggy-backed) responses
				Exchange prev = deduplicator.find(idByMID);
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
			// we have received a Response matching the Request of an ongoing Exchange
			Exchange prev = deduplicator.findPrevious(idByMID, exchange);
			if (prev != null) { // (and thus it holds: prev == exchange)
				LOGGER.log(Level.FINER, "Received duplicate response for open exchange: {0}", response);
				response.setDuplicate(true);
			} else {
				// we have received the expected response for the original request
				idByMID = new KeyMID(exchange.getCurrentRequest().getMID());
				exchangesByMID.remove(idByMID);
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
		} else if (exchange.getCorrelationContext() instanceof DtlsCorrelationContext) {
			// original request has been sent via a DTLS protected transport
			DtlsCorrelationContext exchangeDtlsContext = (DtlsCorrelationContext) exchange.getCorrelationContext();
			// check if the response has been received in the same DTLS session
			if (useStrictResponseMatching) {
				return isResponseStrictlyRelatedToDtlsRequest(exchangeDtlsContext, responseContext);
			} else {
				return isResponseRelatedToDtlsRequest(exchangeDtlsContext, responseContext);
			}
		} else {
			// compare message context used for sending original request to context
			// the response has been received in
			return exchange.getCorrelationContext().equals(responseContext);
		}
	}

	private boolean isResponseRelatedToDtlsRequest(final DtlsCorrelationContext requestContext, final CorrelationContext responseContext) {
		if (responseContext == null) {
			return false;
		} else {
			return requestContext.getSessionId().equals(responseContext.get(DtlsCorrelationContext.KEY_SESSION_ID))
					&& requestContext.getCipher().equals(responseContext.get(DtlsCorrelationContext.KEY_CIPHER));
		}
	}

	private boolean isResponseStrictlyRelatedToDtlsRequest(final DtlsCorrelationContext requestContext, final CorrelationContext responseContext) {
		if (responseContext == null) {
			return false;
		} else {
			return requestContext.getSessionId().equals(responseContext.get(DtlsCorrelationContext.KEY_SESSION_ID))
					&& requestContext.getEpoch().equals(responseContext.get(DtlsCorrelationContext.KEY_EPOCH))
					&& requestContext.getCipher().equals(responseContext.get(DtlsCorrelationContext.KEY_CIPHER));
		}
	}

	public Exchange receiveEmptyMessage(final EmptyMessage message) {

		// local namespace
		KeyMID idByMID = new KeyMID(message.getMID());

		Exchange exchange = exchangesByMID.get(idByMID);

		if (exchange != null) {
			LOGGER.log(Level.FINE, "Exchange got reply: Cleaning up {0}", idByMID);
			exchangesByMID.remove(idByMID);
		} else {
			LOGGER.log(Level.FINE,
					"Ignoring unmatchable empty message from {0}:{1}: {2}",
					new Object[]{message.getSource(), message.getSourcePort(), message});
		}
		return exchange;
	}

	public void clear() {
		this.exchangesByMID.clear();
		this.exchangesByToken.clear();
		this.ongoingExchanges.clear();
		deduplicator.clear();
	}

	private void removeNotificationsOf(ObserveRelation relation) {
		LOGGER.fine("Remove all remaining NON-notifications of observe relation");
		for (Iterator<Response> iterator = relation.getNotificationIterator(); iterator.hasNext();) {
			Response previous = iterator.next();
			// notifications are local MID namespace
			KeyMID idByMID = new KeyMID(previous.getMID(), null, 0);
			exchangesByMID.remove(idByMID);
			iterator.remove();
		}
	}

	/**
	 * Creates a new token that is never the empty token (i.e., always 1-8 bytes).
	 * @return the new token
	 */
	private KeyToken createUnusedToken() {

		Random random = ThreadLocalRandom.current();
		byte[] token;
		KeyToken result;
		do {
			// random length between 1 and tokenSizeLimit
			// TODO: why would we want to have a random length token?
			token = new byte[random.nextInt(tokenSizeLimit)+1];
			// random value
			random.nextBytes(token);
			result = new KeyToken(token);
		} while (exchangesByToken.get(result) != null);

		return result;
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

				KeyMID idByMID = new KeyMID(exchange.getCurrentRequest().getMID());
				KeyToken idByToken = new KeyToken(exchange.getCurrentRequest().getToken());

//				LOGGER.log(Level.FINE, "Exchange completed: Cleaning up {0}", idByToken);
				exchangesByToken.remove(idByToken);

				// in case an empty ACK was lost
				exchangesByMID.remove(idByMID);

			} else { // Origin.REMOTE
				// this endpoint created the Exchange to respond to a request

				Response response = exchange.getCurrentResponse();
				if (response != null && response.getType() != Type.ACK) {
					// only response MIDs are stored for ACK and RST, no reponse Tokens
					KeyMID midKey = new KeyMID(response.getMID(), null, 0);
//					LOGGER.log(Level.FINE, "Remote ongoing completed, cleaning up {0}", midKey);
					exchangesByMID.remove(midKey);
				}

				Request request = exchange.getCurrentRequest();
				if (request != null && (request.getOptions().hasBlock1() || response.getOptions().hasBlock2()) ) {
					KeyUri uriKey = new KeyUri(request.getURI(), request.getSource().getAddress(), request.getSourcePort());
					LOGGER.log(Level.FINE, "Remote ongoing completed, cleaning up ", uriKey);
					ongoingExchanges.remove(uriKey);
				}

				// Remove all remaining NON-notifications if this exchange is an observe relation
				ObserveRelation relation = exchange.getRelation();
				if (relation != null) {
					removeNotificationsOf(relation);
				}
			}
		}

		@Override
		public void contextEstablished(final Exchange exchange) {
			// do nothing
		}
	}
}
