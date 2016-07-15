/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Matthias Kovatsch - creator and main architect
 * Martin Lanter - architect and re-implementation
 * Dominique Im Obersteg - parsers and initial implementation
 * Daniel Pauli - parsers and initial implementation
 * Kai Hudalla - logging
 * Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 * explicit String concatenation
 * Bosch Software Innovations GmbH - use correlation context to improve matching
 * of Response(s) to Request (fix GitHub issue #1)
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.CorrelationContext;

import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Matcher that runs over reliable TCP/TLS protocol. Based on
 * <a href="https://tools.ietf.org/html/draft-ietf-core-coap-tcp-tls-02"/>
 */
public class TcpMatcher implements Matcher {

	private static final Logger LOGGER = Logger.getLogger(UdpMatcher.class.getCanonicalName());

	private final ConcurrentHashMap<Exchange.KeyToken, Exchange> exchangesByToken; // for outgoing
	private final ConcurrentHashMap<Exchange.KeyUri, Exchange> ongoingExchanges; // for blockwise
	private final ExchangeObserver exchangeObserver = new ExchangeObserverImpl();

	/* limit the token size to save bytes in closed environments */
	private final int tokenSizeLimit;
	/* Health status output */
	private final Level healthStatusLevel;
	private final int healthStatusInterval; // seconds

	private boolean started;

	/* the executor, by default the one of the protocol stage */
	private ScheduledExecutorService executor;

	public TcpMatcher(final NetworkConfig config) {
		this.exchangesByToken = new ConcurrentHashMap<>();
		this.ongoingExchanges = new ConcurrentHashMap<>();

		tokenSizeLimit = config.getInt(NetworkConfig.Keys.TOKEN_SIZE_LIMIT);
		if (LOGGER.isLoggable(Level.CONFIG)) {
			LOGGER.log(Level.CONFIG, "Matcher uses {0}={1}",
					new Object[] { NetworkConfig.Keys.TOKEN_SIZE_LIMIT, tokenSizeLimit });
		}

		healthStatusLevel = Level.parse(config.getString(NetworkConfig.Keys.HEALTH_STATUS_PRINT_LEVEL));
		healthStatusInterval = config.getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL);
	}

	@Override public synchronized void start() {
		if (executor == null) {
			throw new IllegalStateException("Matcher has no executor to publish health status.");
		} else if (!started) {
			started = true;

			// this is a useful health metric that could later be exported to some kind of monitoring interface
			if (LOGGER.isLoggable(healthStatusLevel)) {
				executor.scheduleAtFixedRate(new Runnable() {

					@Override public void run() {
						LOGGER.log(healthStatusLevel, "Matcher state: {0} exchangesByToken, {1} ongoingExchanges",
								new Object[] { exchangesByToken.size(), ongoingExchanges.size() });
					}
				}, healthStatusInterval, healthStatusInterval, TimeUnit.SECONDS);
			}
		}
	}

	@Override public synchronized void stop() {
		if (started) {
			started = false;
			clear();
		}
	}

	@Override public synchronized void setExecutor(final ScheduledExecutorService executor) {
		this.executor = executor;
		// health status runnable is not migrated at the moment
	}

	@Override public void sendRequest(Exchange exchange, Request request) {

		// ensure Token is set
		Exchange.KeyToken idByToken;
		if (request.getToken() == null) {
			idByToken = createUnusedToken();
			request.setToken(idByToken.token);
		} else {
			idByToken = new Exchange.KeyToken(request.getToken());
			// ongoing requests may reuse token
			if (!(exchange.getFailedTransmissionCount() > 0 || request.getOptions().hasBlock1() || request.getOptions()
					.hasBlock2() || request.getOptions().hasObserve()) && exchangesByToken.get(idByToken) != null) {
				LOGGER.log(Level.WARNING, "Manual token overrides existing open request: {0}", idByToken);
			}
		}

		exchange.setObserver(exchangeObserver);
		LOGGER.log(Level.FINE, "Tracking open request using {0}", new Object[] { idByToken });

		exchangesByToken.put(idByToken, exchange);
	}

	@Override public void sendResponse(Exchange exchange, Response response) {

		// ensure Token is set
		response.setToken(exchange.getCurrentRequest().getToken());

		// Blockwise transfers are identified by URI and remote endpoint
		if (response.getOptions().hasBlock2()) {
			Request request = exchange.getCurrentRequest();
			Exchange.KeyUri idByUri = new Exchange.KeyUri(request.getURI(), response.getDestination().getAddress(),
					response.getDestinationPort());
			// Observe notifications only send the first block, hence do not store them as ongoing
			if (exchange.getResponseBlockStatus() != null && !response.getOptions().hasObserve()) {
				// Remember ongoing blockwise GET requests
				if (ongoingExchanges.put(idByUri, exchange) == null) {
					LOGGER.log(Level.FINE, "Ongoing Block2 started late, storing {0} for {1}",
							new Object[] { idByUri, request });
				} else {
					LOGGER.log(Level.FINE, "Ongoing Block2 continued, storing {0} for {1}",
							new Object[] { idByUri, request });
				}
			} else {
				LOGGER.log(Level.FINE, "Ongoing Block2 completed, cleaning up {0} for {1}",
						new Object[] { idByUri, request });
				ongoingExchanges.remove(idByUri);
			}
		}

		// Only Observes keep the exchange active
		if (response.isLast()) {
			exchange.setComplete();
		}
	}

	@Override public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		// ensure Token is set
		message.setToken(new byte[0]);
	}

	@Override public Exchange receiveRequest(Request request) {
		/*
		 * The differentiation between the case where there is a Block1 or
		 * Block2 option and the case where there is none has the advantage that
		 * all exchanges that do not need blockwise transfer have simpler and
		 * faster code than exchanges with blockwise transfer.
		 */
		if (!request.getOptions().hasBlock1() && !request.getOptions().hasBlock2()) {

			Exchange exchange = new Exchange(request, Exchange.Origin.REMOTE);
			exchange.setObserver(exchangeObserver);
			return exchange;
		} else {
			Exchange.KeyUri idByUri = new Exchange.KeyUri(request.getURI(), request.getSource().getAddress(),
					request.getSourcePort());
			LOGGER.log(Level.FINE, "Looking up ongoing exchange for {0}", idByUri);

			Exchange ongoing = ongoingExchanges.get(idByUri);
			if (ongoing != null) {
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

				Exchange exchange = new Exchange(request, Exchange.Origin.REMOTE);
				LOGGER.log(Level.FINER, "New ongoing request, storing {0} for {1}", new Object[] { idByUri, request });
				exchange.setObserver(exchangeObserver);
				ongoingExchanges.put(idByUri, exchange);
				return exchange;
			} // if ongoing
		} // if blockwise
	}

	@Override public Exchange receiveResponse(final Response response, final CorrelationContext responseContext) {

		Exchange.KeyToken idByToken = new Exchange.KeyToken(response.getToken());
		Exchange exchange = exchangesByToken.get(idByToken);

		if (exchange == null) {
			// There is no exchange with the given token - ignore response
			return null;
		} else if (isResponseRelatedToRequest(exchange, responseContext)) {
			return exchange;
		} else {
			LOGGER.log(Level.INFO,
					"Ignoring potentially forged response for token {0} with non-matching correlation context",
					idByToken);
			return null;
		}
	}

	private boolean isResponseRelatedToRequest(final Exchange exchange, final CorrelationContext responseContext) {
		return exchange.getCorrelationContext() == null || exchange.getCorrelationContext().equals(responseContext);
	}

	@Override public Exchange receiveEmptyMessage(final EmptyMessage message) {
		return null;
	}

	@Override public void clear() {
		this.exchangesByToken.clear();
		this.ongoingExchanges.clear();
	}

	/**
	 * Creates a new token that is never the empty token (i.e., always 1-8 bytes).
	 * @return the new token
	 */
	private Exchange.KeyToken createUnusedToken() {

		Random random = ThreadLocalRandom.current();
		byte[] token;
		Exchange.KeyToken result;
		do {
			token = new byte[tokenSizeLimit];
			random.nextBytes(token);
			result = new Exchange.KeyToken(token);
		} while (exchangesByToken.get(result) != null);

		return result;
	}

	private class ExchangeObserverImpl implements ExchangeObserver {

		@Override public void completed(final Exchange exchange) {
			if (exchange.getOrigin() == Exchange.Origin.LOCAL) {
				// this endpoint created the Exchange by issuing a request
				Exchange.KeyToken idByToken = new Exchange.KeyToken(exchange.getCurrentRequest().getToken());
				exchangesByToken.remove(idByToken);
			} else { // Origin.REMOTE
				// this endpoint created the Exchange to respond to a request
				Response response = exchange.getCurrentResponse();

				Request request = exchange.getCurrentRequest();
				if (request != null && (request.getOptions().hasBlock1() || response.getOptions().hasBlock2())) {
					Exchange.KeyUri uriKey = new Exchange.KeyUri(request.getURI(), request.getSource().getAddress(),
							request.getSourcePort());
					LOGGER.log(Level.FINE, "Remote ongoing completed, cleaning up ", uriKey);
					ongoingExchanges.remove(uriKey);
				}
			}
		}

		@Override public void contextEstablished(final Exchange exchange) {
			// do nothing
		}
	}

}
