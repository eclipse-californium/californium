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
 * Achim Kraus (Bosch Software Innovations GmbH) - processing of notifies according UdpMatcher.
 * Achim Kraus (Bosch Software Innovations GmbH) - add Exchange to removes.
 * Achim Kraus (Bosch Software Innovations GmbH) - make exchangeStore final
 * Achim Kraus (Bosch Software Innovations GmbH) - reset blockwise-cleanup on 
 *                                                 complete exchange. Issue #103
 * Achim Kraus (Bosch Software Innovations GmbH) - release all tokens except of
 *                                                 starting observe requests
 * Achim Kraus (Bosch Software Innovations GmbH) - remove contextEstablished.
 *                                                 issue #311
 ******************************************************************************/
package org.eclipse.californium.core.network;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.KeyToken;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.CorrelationContext;

/**
 * Matcher that runs over reliable TCP/TLS protocol. Based on
 * <a href="https://tools.ietf.org/html/draft-ietf-core-coap-tcp-tls-02"/>
 */
public final class TcpMatcher extends BaseMatcher {

	private static final Logger LOGGER = Logger.getLogger(TcpMatcher.class.getName());
	private final ExchangeObserver exchangeObserver = new ExchangeObserverImpl();

	/**
	 * Creates a new matcher for running CoAP over TCP.
	 * 
	 * @param config the configuration to use.
	 * @throws NullPointerException if the configuration, notification listener,
	 *             or the observation store is {@code null}.
	 */
	public TcpMatcher(final NetworkConfig config, final MessageExchangeStore exchangeStore) {
		super(config, exchangeStore);
	}

	@Override
	public void sendRequest(Exchange exchange, final Request request) {

		exchange.setObserver(exchangeObserver);
		exchangeStore.registerOutboundRequestWithTokenOnly(exchange);
		LOGGER.log(Level.FINE, "Tracking open request using {0}", new Object[] { request.getTokenString() });
	}

	@Override
	public void sendResponse(Exchange exchange, Response response) {

		// ensure Token is set
		response.setToken(exchange.getCurrentRequest().getToken());

		// Blockwise transfers are identified by URI and remote endpoint
		if (response.getOptions().hasBlock2()) {
			Request request = exchange.getCurrentRequest();
			Exchange.KeyUri idByUri = new Exchange.KeyUri(request.getURI(), response.getDestination().getAddress(),
					response.getDestinationPort());
			// Observe notifications only send the first block, hence do not
			// store them as ongoing
			if (exchange.getResponseBlockStatus() != null && !response.getOptions().hasObserve()) {
				// Remember ongoing blockwise GET requests
				if (exchangeStore.registerBlockwiseExchange(idByUri, exchange) == null) {
					LOGGER.log(Level.FINE, "Ongoing Block2 started late, storing {0} for {1}", new Object[] { idByUri,
							request });
				} else {
					LOGGER.log(Level.FINE, "Ongoing Block2 continued, storing {0} for {1}", new Object[] { idByUri,
							request });
				}
			} else {
				LOGGER.log(Level.FINE, "Ongoing Block2 completed, cleaning up {0} for {1}", new Object[] { idByUri,
						request });
				exchangeStore.remove(idByUri, exchange);
			}
		}

		// Only Observes keep the exchange active (CoAP server side)
		if (response.isLast()) {
			exchange.setComplete();
		}
	}

	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		// ensure Token is set
		if (message.isConfirmable()) {
			message.setToken(new byte[0]);
		} else {
			throw new UnsupportedOperationException("sending empty message (ACK/RST) over tcp is not supported!");
		}
	}

	@Override
	public Exchange receiveRequest(Request request) {
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

			Exchange ongoing = exchangeStore.get(idByUri);
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
				exchangeStore.registerBlockwiseExchange(idByUri, exchange);
				return exchange;
			} // if ongoing
		} // if blockwise
	}

	@Override
	public Exchange receiveResponse(final Response response, final CorrelationContext responseContext) {

		final Exchange.KeyToken idByToken = Exchange.KeyToken.fromInboundMessage(response);
		Exchange exchange = exchangeStore.get(idByToken);

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

	@Override
	public Exchange receiveEmptyMessage(final EmptyMessage message) {
		/* ignore received empty messages via tcp */
		return null;
	}

	private class ExchangeObserverImpl implements ExchangeObserver {

		@Override
		public void completed(final Exchange exchange) {
			if (exchange.isComplete()) {
				// not for completeCurrentRequest
				exchange.setBlockCleanupHandle(null);
			}
			if (exchange.getOrigin() == Exchange.Origin.LOCAL) {
				// this endpoint created the Exchange by issuing a request
				Request originRequest = exchange.getCurrentRequest();
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
					if(!originRequest.isObserve()) {
						exchangeStore.releaseToken(idByToken);
					}
					LOGGER.log(Level.FINER, "Exchange [{0}, origin: {1}] completed", new Object[]{idByToken, exchange.getOrigin()});
				}
			} else { // Origin.REMOTE
				// this endpoint created the Exchange to respond to a request
				Response response = exchange.getCurrentResponse();

				Request request = exchange.getCurrentRequest();
				if (request != null && (request.getOptions().hasBlock1() || response.getOptions().hasBlock2())) {
					Exchange.KeyUri uriKey = new Exchange.KeyUri(request.getURI(), request.getSource().getAddress(),
							request.getSourcePort());
					LOGGER.log(Level.FINE, "Remote ongoing completed, cleaning up ", uriKey);
					exchangeStore.remove(uriKey, exchange);
				}
			}
		}

	}
}
