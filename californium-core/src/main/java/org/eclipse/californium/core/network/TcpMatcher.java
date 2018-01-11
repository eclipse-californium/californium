/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 * Achim Kraus (Bosch Software Innovations GmbH) - replace isResponseRelatedToRequest
 *                                                 with CorrelationContextMatcher
 *                                                 (fix GitHub issue #104)
 * Achim Kraus (Bosch Software Innovations GmbH) - remove obsolete ExchangeObserver
 *                                                 from matchNotifyResponse.
 *                                                 Add Exchange for save remove.
 * Achim Kraus (Bosch Software Innovations GmbH) - make exchangeStore final
 * Achim Kraus (Bosch Software Innovations GmbH) - release all tokens except of
 *                                                 starting observe requests
 * Achim Kraus (Bosch Software Innovations GmbH) - optimize correlation context
 *                                                 processing. issue #311
 * Achim Kraus (Bosch Software Innovations GmbH) - replace parameter EndpointContext 
 *                                                 by EndpointContext of response.
 * Bosch Software Innovations GmbH - migrate to SLF4J
 * Achim Kraus (Bosch Software Innovations GmbH) - adjust to use Token and KeyToken
 * Achim Kraus (Bosch Software Innovations GmbH) - replace byte array token by Token
 * Achim Kraus (Bosch Software Innovations GmbH) - use key token factory
 ******************************************************************************/
package org.eclipse.californium.core.network;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.observe.ObservationStore;
import org.eclipse.californium.elements.EndpointContextMatcher;

/**
 * Matcher that runs over reliable TCP/TLS protocol. Based on
 * <a href="https://tools.ietf.org/html/draft-ietf-core-coap-tcp-tls-02"/>
 */
public final class TcpMatcher extends BaseMatcher {

	private static final Logger LOGGER = LoggerFactory.getLogger(TcpMatcher.class.getName());
	private final ExchangeObserver exchangeObserver = new ExchangeObserverImpl();
	private final EndpointContextMatcher endpointContextMatcher;

	/**
	 * Creates a new matcher for running CoAP over TCP.
	 * 
	 * @param config the configuration to use.
	 * @param notificationListener the callback to invoke for notifications
	 *            received from peers.
	 * @param observationStore the object to use for keeping track of
	 *            observations created by the endpoint this matcher is part of.
	 * @param exchangeStore The store to use for keeping track of message exchanges.
	 * @param endpointContextMatcher endpoint context matcher to relate
	 *            responses with requests
	 * @throws NullPointerException if the configuration, notification listener,
	 *             or the observation store is {@code null}.
	 */
	public TcpMatcher(final NetworkConfig config, final NotificationListener notificationListener,
			 final ObservationStore observationStore, final MessageExchangeStore exchangeStore, 
			 final EndpointContextMatcher endpointContextMatcher, final KeyTokenFactory keyTokenFactory) {
		super(config, notificationListener, observationStore, exchangeStore, keyTokenFactory);
		this.endpointContextMatcher = endpointContextMatcher;
	}

	@Override
	public void sendRequest(Exchange exchange, final Request request) {

		exchange.setObserver(exchangeObserver);
		exchangeStore.registerOutboundRequestWithTokenOnly(keyTokenFactory, exchange);
		LOGGER.debug("tracking open request using {}", request.getTokenString());

		if (request.isObserve()) {
			registerObserve(request);
		}
	}

	@Override
	public void sendResponse(Exchange exchange, Response response) {

		// ensure Token is set
		response.setToken(exchange.getCurrentRequest().getToken());

		// Only Observes keep the exchange active (CoAP server side)
		if (response.isLast()) {
			exchange.setComplete();
		}
	}

	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		// ensure Token is set
		if (message.isConfirmable()) {
			message.setToken(Token.EMPTY);
		} else {
			throw new UnsupportedOperationException("sending empty message (ACK/RST) over tcp is not supported!");
		}
	}

	@Override
	public Exchange receiveRequest(Request request) {

		Exchange exchange = new Exchange(request, Exchange.Origin.REMOTE);
		exchange.setObserver(exchangeObserver);
		return exchange;
	}

	@Override
	public Exchange receiveResponse(final Response response) {

		final KeyToken idByToken = keyTokenFactory.create(response.getToken(), response.getSourceContext());
		Exchange exchange = exchangeStore.get(idByToken);

		if (exchange == null) {
			// we didn't find a message exchange for the token from the response
			// that is scoped to the response's source endpoint address
			// let's try to find an existing observation for the token
			// NOTE this approach is very prone to faked notifications
			// because we do not check that the notification's sender is
			// the same as the receiver of the original observe request
			// TODO: assert that notification's source endpoint is correct
			exchange = matchNotifyResponse(response);
		}

		if (exchange == null) {
			// There is no exchange with the given token - ignore response
			return null;
		} else if (endpointContextMatcher.isResponseRelatedToRequest(exchange.getEndpointContext(), response.getSourceContext())) {
			return exchange;
		} else {
			LOGGER.info(
					"ignoring potentially forged response for token {} with non-matching endpoint context",
					idByToken);
			return null;
		}
	}

	@Override
	public Exchange receiveEmptyMessage(final EmptyMessage message) {
		/* ignore received empty messages via tcp */
		return null;
	}

	private class ExchangeObserverImpl implements ExchangeObserver {

		@Override
		public void completed(final Exchange exchange) {
			if (exchange.getOrigin() == Exchange.Origin.LOCAL) {
				// this endpoint created the Exchange by issuing a request
				Request originRequest = exchange.getCurrentRequest();
				if (originRequest.getToken() == null) {
					// this should not happen because we only register the observer
					// if we have successfully registered the exchange
					LOGGER.warn(
							"exchange observer has been completed on unregistered exchange [peer: {}, origin: {}]",
							new Object[]{ originRequest.getDestinationContext().getPeerAddress(),
									exchange.getOrigin()});
				} else {
					KeyToken idByToken = keyTokenFactory.create(originRequest.getToken(), originRequest.getDestinationContext());
					exchangeStore.remove(idByToken, exchange);
					if(!originRequest.isObserve()) {
						exchangeStore.releaseToken(idByToken.getToken());
					}
					LOGGER.debug("Exchange [{}, origin: {}] completed", new Object[]{idByToken, exchange.getOrigin()});
				}

			} else { // Origin.REMOTE
				// nothing to do
			}
		}

		@Override
		public void contextEstablished(final Exchange exchange) {
			Request request = exchange.getRequest(); 
			if (request != null && request.isObserve()) {
				KeyToken idByToken = keyTokenFactory.create(request.getToken(), request.getDestinationContext());
				observationStore.setContext(idByToken, exchange.getEndpointContext());
			}
		}
	}
}
