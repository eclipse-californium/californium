/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.extplugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.BAD_OPTION;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.INTERNAL_SERVER_ERROR;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.SERVICE_UNAVAILABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_OCTET_STREAM;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.util.ArrayList;
import java.util.Arrays;
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
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.ResponseTimeout;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.coap.UriQueryParameter;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.exception.EndpointUnconnectedException;
import org.eclipse.californium.elements.util.DatagramWriter;
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
 * <dd>number of notifies before the observation is reregistered. 0 to cancel a
 * established observation</dd>
 * <dt>res=path</dt>
 * <dd>path of resource to observe.</dd>
 * </dl>
 * 
 * Additional query parameter will be send with the observer request.
 * 
 * Example:
 * 
 * <pre>
 * coap://localhost:5783/reverse-observe?obs=25&res=feed-CON&rlen=400
 * </pre>
 * 
 * Will request an observation from the origin peer using
 * 
 * <pre>
 * coap://localhost:???/feed-CON?rlen=400
 * </pre>
 * 
 * (Please refer to the documentation of the Feed resource in the extplugtest
 * client. "feed-CON" resource will send notifies using CON, "feed-NON" using
 * NON)
 */
public class ReverseObserve extends CoapResource implements NotificationListener {

	private static final Logger LOGGER = LoggerFactory.getLogger(ReverseObserve.class);
	private static final Logger HEALTH_LOGGER = LoggerFactory.getLogger(LOGGER.getName() + ".health");

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
	 * URI query parameter to specify reverse observation.
	 */
	private static final String URI_QUERY_OPTION_TIMEOUT = "timeout";
	/**
	 * Supported query parameter.
	 * 
	 * @since 3.2
	 */
	private static final List<String> SUPPORTED = Arrays.asList(URI_QUERY_OPTION_OBSERVE, URI_QUERY_OPTION_RESOURCE,
			URI_QUERY_OPTION_TIMEOUT);
	/**
	 * Maximum number of notifies before reregister is triggered.
	 */
	private static final int MAX_NOTIFIES = 10000000;
	/**
	 * Timeout for response in milliseconds.
	 */
	private static final int RESPONSE_TIMEOUT_MILLIS = 120000;

	/**
	 * Observation tokens by peer address.
	 */
	private final ConcurrentMap<String, ObservationRequest> observesByPeer = new ConcurrentHashMap<String, ObservationRequest>();
	/**
	 * Observations by token.
	 */
	private final ConcurrentMap<Token, Observation> observesByToken = new ConcurrentHashMap<Token, Observation>();

	private final ConcurrentMap<Token, String> peersByToken = new ConcurrentHashMap<Token, String>();

	/**
	 * Overall received notifications.
	 */
	private final AtomicLong overallNotifies = new AtomicLong();
	/**
	 * Overall received notifications.
	 */
	private final AtomicLong overallObserves = new AtomicLong();
	/**
	 * Scheduler for notification timeout.
	 */
	private final ScheduledExecutorService executor;

	/**
	 * Create reverse observation resource.
	 * 
	 * @param config configuration to read HEALTH_STATUS_INTERVAL.
	 * @param executor executor for notification timeout.
	 */
	public ReverseObserve(Configuration config, ScheduledExecutorService executor) {
		super(RESOURCE_NAME);
		this.executor = executor;
		getAttributes().setTitle("Reverse Observe");
		getAttributes().addContentType(TEXT_PLAIN);
		getAttributes().addContentType(APPLICATION_OCTET_STREAM);
		long healthStatusInterval = config.get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS);
		if (healthStatusInterval > 0 && HEALTH_LOGGER.isDebugEnabled()) {
			executor.scheduleWithFixedDelay(new Runnable() {

				@Override
				public void run() {
					if (overallNotifies.get() > 0) {
						HEALTH_LOGGER.debug("{} observes, {} by peers", observesByToken.size(), observesByPeer.size());
						HEALTH_LOGGER.debug("{} notifies overall, {} observes overall", overallNotifies.get(),
								overallObserves.get());
					}
				}
			}, healthStatusInterval, healthStatusInterval, TimeUnit.MILLISECONDS);
		}
	}

	@Override
	public void handlePOST(CoapExchange exchange) {

		// get request to read out details
		Request request = exchange.advanced().getRequest();

		int accept = request.getOptions().getAccept();
		if (accept != UNDEFINED && accept != TEXT_PLAIN && accept != APPLICATION_OCTET_STREAM) {
			exchange.respond(NOT_ACCEPTABLE);
			return;
		}
		IncomingExchange incomingExchange = new IncomingExchange(exchange);
		if (!incomingExchange.isProcessed()) {
			processPOST(incomingExchange);
		}
	}

	private void processPOST(IncomingExchange exchange) {
		Request request = exchange.getRequest();
		String resource = exchange.getUriPath();
		Integer observe = exchange.getObserves();
		List<String> observeUriQuery = exchange.getUriQuery();

		if (observe != null && resource != null) {
			Endpoint endpoint = exchange.getEndpoint();
			String key = exchange.getPeerKey();
			ObservationRequest pendingObservation = observesByPeer.putIfAbsent(key,
					new ObservationRequest(exchange, Token.EMPTY));
			if (pendingObservation != null && pendingObservation.getObservationToken().equals(Token.EMPTY)) {
				LOGGER.warn("Too many requests from {} (pending {}, current {})", key,
						pendingObservation.getIncomingExchange().getRequest().getMID(), request.getMID());
				exchange.respond(SERVICE_UNAVAILABLE);
			} else {
				if (observe > 0) {
					exchange.accept();
					Request observeRequest = Request.newGet();
					if (pendingObservation != null) {
						observeRequest.setToken(pendingObservation.getObservationToken());
					}
					observeRequest.getOptions().setUriPath(resource);
					observeRequest.getOptions().setObserve(0);
					for (String query : observeUriQuery) {
						observeRequest.getOptions().addUriQuery(query);
					}
					observeRequest.setDestinationContext(request.getSourceContext());
					observeRequest.addMessageObserver(new RequestObserver(exchange, observeRequest, observe));
					observeRequest
							.addMessageObserver(new ResponseTimeout(observeRequest, RESPONSE_TIMEOUT_MILLIS, executor));
					observeRequest.send(endpoint);
					overallObserves.incrementAndGet();
				} else {
					if (pendingObservation != null) {
						LOGGER.info("Requested cancel observation {}", pendingObservation.getObservationToken());
						endpoint.cancelObservation(pendingObservation.getObservationToken());
						exchange.respond(CHANGED);
					} else {
						LOGGER.info("Requested cancel not established observation for {}", key);
						exchange.respond(CHANGED);
					}
				}
			}
		} else if (request.getOptions().getAccept() != APPLICATION_OCTET_STREAM) {
			exchange.respond(CHANGED,
					observesByPeer.size() + " active observes, " + overallNotifies.get() + " notifies.", TEXT_PLAIN);
		} else {
			DatagramWriter writer = new DatagramWriter(12);
			writer.writeLong(observesByPeer.size(), 32);
			writer.writeLong(overallNotifies.get(), 64);
			exchange.respond(CHANGED, writer.toByteArray(), APPLICATION_OCTET_STREAM);
			writer.close();
		}
	}

	@Override
	public void onNotification(Request request, Response response) {
		overallNotifies.incrementAndGet();
		Token token = response.getToken();
		Observation observation = observesByToken.get(token);
		if (observation != null) {
			observation.onNotification();
		} else {
			String peer = peersByToken.get(token);
			if (peer != null) {
				LOGGER.info("Notification {} from old observe: {}", response, peer);
			} else {
				LOGGER.info("Notification {} from unkown observe", response);
			}
		}
	}

	private class IncomingExchange {

		private final CoapExchange incomingExchange;
		private final int accept;
		private final int timeout;
		private final String resource;
		private final Integer observe;
		private final List<String> observeUriQuery = new ArrayList<>();
		private final AtomicBoolean processed = new AtomicBoolean();

		private IncomingExchange(CoapExchange incomingExchange) {
			this.incomingExchange = incomingExchange;
			Request request = incomingExchange.advanced().getRequest();
			this.accept = request.getOptions().getAccept();
			int timeout = 30;
			Integer observe = null;
			String resource = null;
			try {
				UriQueryParameter helper = request.getOptions().getUriQueryParameter(SUPPORTED, observeUriQuery);
				resource = helper.getArgument(URI_QUERY_OPTION_RESOURCE, null);
				timeout = helper.getArgumentAsInteger(URI_QUERY_OPTION_TIMEOUT, timeout, 0);
				if (helper.hasParameter(URI_QUERY_OPTION_OBSERVE)) {
					observe = helper.getArgumentAsInteger(URI_QUERY_OPTION_OBSERVE, 0, 0, MAX_NOTIFIES);
				}
			} catch (IllegalArgumentException ex) {
				respond(BAD_OPTION, ex.getMessage(), MediaTypeRegistry.UNDEFINED);
			}

			this.resource = resource;
			this.observe = observe;
			this.timeout = timeout;
		}

		private void accept() {
			incomingExchange.accept();
		}

		private void respond(ResponseCode code) {
			if (processed.compareAndSet(false, true)) {
				incomingExchange.respond(code);
			}
		}

		private void respond(ResponseCode code, byte[] payload, int contentFormat) {
			if (processed.compareAndSet(false, true)) {
				incomingExchange.respond(code, payload, contentFormat);
			}
		}

		private void respond(ResponseCode code, String payload, int contentFormat) {
			if (processed.compareAndSet(false, true)) {
				incomingExchange.respond(code, payload, contentFormat);
			}
		}

		private boolean isProcessed() {
			return processed.get();
		}

		private int getAccept() {
			return accept;
		}

		private String getUriPath() {
			return resource;
		}

		private Integer getObserves() {
			return observe;
		}

		private int getTimeout() {
			return timeout;
		}

		private List<String> getUriQuery() {
			return observeUriQuery;
		}

		private Request getRequest() {
			return incomingExchange.advanced().getRequest();
		}

		private String getPeerKey() {
			Request request = getRequest();
			return request.getScheme() + "://" + request.getSourceContext().getPeerAddress() + "?" + resource;
		}

		private Endpoint getEndpoint() {
			return incomingExchange.advanced().getEndpoint();
		}
	}

	private class RequestObserver extends MessageObserverAdapter {

		private final IncomingExchange incomingExchange;
		private final Request outgoingObserveRequest;
		private final AtomicBoolean registered = new AtomicBoolean();
		private final int count;
		private boolean failureLogged;

		private RequestObserver(IncomingExchange incomingExchange, Request outgoingObserveRequest, int count) {
			this.incomingExchange = incomingExchange;
			this.outgoingObserveRequest = outgoingObserveRequest;
			this.count = count;
		}

		@Override
		public void onResponse(final Response response) {
			Token token = response.getToken();
			if (response.isError()) {
				LOGGER.info("Observation response error: {} {}", outgoingObserveRequest.getScheme(),
						response.getCode());
				remove(response.getCode());
			} else if (response.isNotification()) {
				if (registered.compareAndSet(false, true)) {
					String key = incomingExchange.getPeerKey();
					Endpoint endpoint = incomingExchange.getEndpoint();
					ObservationRequest previous = observesByPeer.put(key,
							new ObservationRequest(incomingExchange, token));
					if (previous != null && !previous.getObservationToken().equals(Token.EMPTY)
							&& !token.equals(previous.getObservationToken())) {
						LOGGER.info("Cancel previous observation {}", token);
						endpoint.cancelObservation(previous.getObservationToken());
					}
					peersByToken.put(token, key);
					observesByToken.put(token, new Observation(incomingExchange, token, count));
					if (!incomingExchange.isProcessed()) {
						if (incomingExchange.getAccept() != APPLICATION_OCTET_STREAM) {
							incomingExchange.respond(CHANGED, token.getAsString(), TEXT_PLAIN);
						} else {
							incomingExchange.respond(CHANGED, token.getBytes(), APPLICATION_OCTET_STREAM);
						}
					}
				}
			} else {
				LOGGER.info("Observation {} {} not established!", outgoingObserveRequest.getScheme(),
						outgoingObserveRequest.getToken());
				remove(NOT_ACCEPTABLE);
			}
		}

		@Override
		public void onSendError(Throwable error) {
			if (error instanceof ConnectorException) {
				if (!(error instanceof EndpointUnconnectedException)) {
					LOGGER.warn("Observe request failed! {} {} {}", outgoingObserveRequest.getScheme(),
							outgoingObserveRequest.getToken(), error.getMessage());
				}
				failureLogged = true;
			}
			super.onSendError(error);
		}

		@Override
		protected void failed() {
			if (!failureLogged) {
				LOGGER.debug("Observe request failed! {} {}", outgoingObserveRequest.getScheme(),
						outgoingObserveRequest.getToken());
			}
			remove(INTERNAL_SERVER_ERROR);
		}

		private void remove(ResponseCode code) {
			String key = incomingExchange.getPeerKey();
			observesByPeer.remove(key);
			LOGGER.info("Removed observation for {}", key);
			incomingExchange.respond(code);
		}
	}

	private class ObservationRequest {

		private final IncomingExchange incomingExchange;
		private final Token observationToken;

		private ObservationRequest(IncomingExchange incomingExchange, Token observationToken) {
			this.incomingExchange = incomingExchange;
			this.observationToken = observationToken;
		}

		private Token getObservationToken() {
			return observationToken;
		}

		private IncomingExchange getIncomingExchange() {
			return incomingExchange;
		}
	}

	private class Observation {

		private final IncomingExchange incomingExchange;
		private final Token observationToken;
		private final AtomicInteger countDown;
		private final AtomicReference<Future<?>> timeout = new AtomicReference<Future<?>>();

		private Observation(IncomingExchange incomingExchange, Token observationToken, int count) {
			this.incomingExchange = incomingExchange;
			this.observationToken = observationToken;
			this.countDown = new AtomicInteger(count);
			scheduleTimeout();
		}

		private void setTimeout(ScheduledFuture<?> future) {
			Future<?> previous = timeout.getAndSet(future);
			if (previous != null) {
				previous.cancel(false);
			}
		}

		private void scheduleTimeout() {
			ScheduledFuture<?> future = executor.schedule(new Runnable() {

				@Override
				public void run() {
					reregister();
				}
			}, incomingExchange.getTimeout(), TimeUnit.SECONDS);
			setTimeout(future);
		}

		private void onNotification() {
			if (countDown.decrementAndGet() == 0) {
				setTimeout(null);
				reregister();
			} else {
				scheduleTimeout();
			}
		}

		private void reregister() {
			String key = incomingExchange.getPeerKey();
			LOGGER.info("Cancel observation {} for {}", observationToken, key);
			incomingExchange.getEndpoint().cancelObservation(observationToken);
			observesByPeer.remove(key);
			observesByToken.remove(observationToken, this);
			LOGGER.info("Restart observation for {}", key);
			processPOST(incomingExchange);
		}
	}

}
