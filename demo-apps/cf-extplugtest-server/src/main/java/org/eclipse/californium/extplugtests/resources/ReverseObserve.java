/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.extplugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.BAD_OPTION;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.INTERNAL_SERVER_ERROR;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.SERVICE_UNAVAILABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_OCTET_STREAM;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reverse observer resource.
 * 
 * POST request send to this resource triggers a reverse observation; a GET
 * observe request is sent back to the original peer of the POST request.
 * 
 * Supported URI query parameter:
 * 
 * <dl>
 * <dt>obs=number</dt>
 * <dd>number of observes before the observation is reregistered.</dd>
 * <dt>res=path</dt>
 * <dd>path of resource to observe.</dd>
 * </dl>
 * 
 * Additional query parameter will be send with the observer request.
 * 
 * Example:
 * 
 * <pre>
 * coap://localhost:5783/reverse-observe?obs=25&res=feed&rlen=400
 * </pre>
 * 
 * Will request an observation from the origin peer using
 * 
 * <pre>
 * coap://localhost:???/feed?rlen=400
 * </pre>
 * 
 */
public class ReverseObserve extends CoapResource implements NotificationListener {

	private static final Logger LOGGER = LoggerFactory.getLogger(ReverseObserve.class.getCanonicalName());

	private static final String RESOURCE_NAME = "reverse-observe";
	/**
	 * URI query parameter to specify reverse observation.
	 */
	private static final String URI_QUERY_OPTION_OBSERVE = "obs";
	/**
	 * URI query parameter to specify reverse observation.
	 */
	private static final String URI_QUERY_OPTION_RESOURCE = "res";
	/**
	 * Maximum number of notifies before reregister is triggered.
	 */
	private static final int MAX_NOTIFIES = 1000;

	/**
	 * Observation tokens by peer address.
	 */
	private ConcurrentMap<String, Token> observesByPeer = new ConcurrentHashMap<String, Token>();
	/**
	 * Observations by token.
	 */
	private ConcurrentMap<Token, Observation> observesByToken = new ConcurrentHashMap<Token, Observation>();
	/**
	 * Overall received notifications.
	 */
	private AtomicLong overallNotifies = new AtomicLong();
	/**
	 * Scheduler for notification timeout.
	 */
	private ScheduledExecutorService executor;

	/**
	 * Create reverse observation resource.
	 * 
	 * @param config network configuration to read HEALTH_STATUS_INTERVAL.
	 * @param executor executor for notification timeout.
	 */
	public ReverseObserve(NetworkConfig config, ScheduledExecutorService executor) {
		super(RESOURCE_NAME);
		this.executor = executor;
		getAttributes().setTitle("Reverse Observe");
		getAttributes().addContentType(TEXT_PLAIN);
		getAttributes().addContentType(APPLICATION_OCTET_STREAM);
		if (LOGGER.isInfoEnabled()) {
			int healthStatusInterval = config.getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL, 60); // seconds
			executor.scheduleWithFixedDelay(new Runnable() {

				@Override
				public void run() {
					if (overallNotifies.get() > 0) {
						LOGGER.info("{} observes, {} by peers", observesByToken.size(), observesByPeer.size());
						LOGGER.info("{} notifies overalls", overallNotifies.get());
					}
				}
			}, healthStatusInterval, healthStatusInterval, TimeUnit.SECONDS);
		}
	}

	/**
	 * Get lookup key based on scheme and peer.
	 * 
	 * @param exchange exchange of request.
	 * @return key
	 */
	private static String getPeerKey(CoapExchange exchange) {
		Request request = exchange.advanced().getRequest();
		return request.getScheme() + "://" + request.getSourceContext().getPeerAddress();
	}

	@Override
	public void handlePOST(CoapExchange exchange) {

		// get request to read out details
		Request request = exchange.advanced().getRequest();

		int accept = request.getOptions().getAccept();
		if (accept != UNDEFINED && accept != APPLICATION_OCTET_STREAM) {
			exchange.respond(NOT_ACCEPTABLE);
			return;
		}

		List<String> observeUriQuery = new ArrayList<>();
		List<String> uriQuery = request.getOptions().getUriQuery();
		Integer observe = null;
		String resource = null;
		for (String query : uriQuery) {
			if (query.startsWith(URI_QUERY_OPTION_OBSERVE + "=")) {
				String message = null;
				String obs = query.substring(URI_QUERY_OPTION_OBSERVE.length() + 1);
				try {
					observe = Integer.parseInt(obs);
					if (observe < 0) {
						message = "URI-query-option " + query + " is negative number!";
					} else if (observe > MAX_NOTIFIES) {
						message = "URI-query-option " + query + " is too large (max. " + MAX_NOTIFIES + ")!";
					}
				} catch (NumberFormatException ex) {
					message = "URI-query-option " + query + " is no number!";
				}
				if (message != null) {
					Response response = Response.createResponse(request, BAD_OPTION);
					response.setPayload(message);
					exchange.respond(response);
					return;
				}
			} else if (query.startsWith(URI_QUERY_OPTION_RESOURCE + "=")) {
				resource = query.substring(URI_QUERY_OPTION_RESOURCE.length() + 1);
			} else {
				observeUriQuery.add(query);
			}
		}

		if (observe != null && resource != null) {
			Endpoint endpoint = exchange.advanced().getEndpoint();
			String key = getPeerKey(exchange);
			Token token = observesByPeer.putIfAbsent(key, Token.EMPTY);
			if (token != null && token.equals(Token.EMPTY)) {
				LOGGER.info("Too many requests from {}", key);
				exchange.respond(SERVICE_UNAVAILABLE);
			}
			else {
				if (observe > 0) {
					Request observeRequest = Request.newGet();
					if (token != null) {
						observeRequest.setToken(token);
					}
					observeRequest.getOptions().setUriPath(resource);
					observeRequest.getOptions().setObserve(0);
					for (String query : observeUriQuery) {
						observeRequest.getOptions().addUriQuery(query);
					}
					observeRequest.setDestinationContext(request.getSourceContext());
					observeRequest.addMessageObserver(new ObserveRequestObserver(exchange, observeRequest, observe));
					observeRequest.send(endpoint);
				} else if (token != null) {
					LOGGER.info("Requested cancel observation {}", token);
					endpoint.cancelObservation(token);
				}
			}
		} else {
			exchange.respond(CONTENT,
					observesByPeer.size() + " active observes, " + overallNotifies.get() + " notifies.", TEXT_PLAIN);
		}
	}

	@Override
	public void onNotification(Request request, Response response) {
		overallNotifies.incrementAndGet();
		Observation observation = observesByToken.get(response.getToken());
		if (observation != null) {
			observation.onNotification();
		}
	}

	private class ObserveRequestObserver extends MessageObserverAdapter {

		private CoapExchange incomingExchange;
		private Request outgoingObserveRequest;
		private AtomicBoolean registered = new AtomicBoolean();
		private int count;

		public ObserveRequestObserver(CoapExchange incomingExchange, Request outgoingObserveRequest, int count) {
			this.incomingExchange = incomingExchange;
			this.outgoingObserveRequest = outgoingObserveRequest;
			this.count = count;
		}

		@Override
		public void onResponse(final Response response) {
			if (response.isError()) {
				LOGGER.info("Observation response error: {}", response.getCode());
				remove(response.getCode());
			} else if (response.isNotification()) {
				if (registered.compareAndSet(false, true)) {
					String key = getPeerKey(incomingExchange);
					Endpoint endpoint = incomingExchange.advanced().getEndpoint();
					Token token = outgoingObserveRequest.getToken();
					Token previous = observesByPeer.put(key, token);
					if (previous != null && !previous.equals(Token.EMPTY) && !token.equals(previous)) {
						LOGGER.info("Cancel previous observation {}", token);
						endpoint.cancelObservation(previous);
					}
					observesByToken.put(token, new Observation(incomingExchange, token, count));
					if (!incomingExchange.advanced().isComplete()) {
						incomingExchange.respond(CONTENT, token.getBytes(), APPLICATION_OCTET_STREAM);
					}
				}
			} else {
				LOGGER.info("Observation {} not established!", outgoingObserveRequest.getToken());
				remove(NOT_ACCEPTABLE);
			}
		}

		@Override
		protected void failed() {
			LOGGER.info("Observe request failed! {}", outgoingObserveRequest.getToken());
			remove(INTERNAL_SERVER_ERROR);
		}

		public void remove(ResponseCode code) {
			String key = getPeerKey(incomingExchange);
			observesByPeer.remove(key);
			LOGGER.info("Removed observation for {}", key);
			if (!incomingExchange.advanced().isComplete()) {
				incomingExchange.respond(code);
			}
		}
	}

	private class Observation {

		private final CoapExchange incomingExchange;
		private final Token token;
		private final AtomicInteger countDown;
		private final AtomicReference<Future<?>> timeout = new AtomicReference<Future<?>>();

		public Observation(CoapExchange incomingExchange, Token token, int count) {
			this.incomingExchange = incomingExchange;
			this.token = token;
			this.countDown = new AtomicInteger(count);
			scheduleTimeout();
		}

		public void setTimeout(ScheduledFuture<?> future) {
			Future<?> previous = timeout.getAndSet(future);
			if (previous != null) {
				previous.cancel(false);
			}
		}

		public void scheduleTimeout() {
			ScheduledFuture<?> future = executor.schedule(new Runnable() {

				@Override
				public void run() {
					reregister();
				}
			}, 30, TimeUnit.SECONDS);
			setTimeout(future);
		}

		public void onNotification() {
			if (countDown.decrementAndGet() == 0) {
				setTimeout(null);
				reregister();
			} else {
				scheduleTimeout();
			}
		}

		public void reregister() {
			String key = getPeerKey(incomingExchange);
			LOGGER.info("Cancel observation {} for {}", token, key);
			incomingExchange.advanced().getEndpoint().cancelObservation(token);
			observesByPeer.remove(key);
			observesByToken.remove(token, this);
			LOGGER.info("Restart observation for {}", key);
			handlePOST(incomingExchange);
		}
	}

}
