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
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CONTENT;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_OCTET_STREAM;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reverse request resource.
 * 
 * POST request send to this resource triggers a reverse request; a GET request
 * is sent back to the original peer of the POST request.
 * 
 * Supported URI query parameter:
 * 
 * <dl>
 * <dt>req=number</dt>
 * <dd>number of requests.</dd>
 * <dt>res=path</dt>
 * <dd>path of resource to request.</dd>
 * </dl>
 * 
 * Additional query parameter will be send with the request.
 * 
 * Example:
 * 
 * <pre>
 * coap://localhost:5783/reverse-request?req=25&res=feed-CON&rlen=400
 * </pre>
 * 
 * Will request from the origin peer
 * 
 * <pre>
 * coap://localhost:???/feed-CON?rlen=400
 * </pre>
 * 
 */
public class ReverseRequest extends CoapResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(ReverseRequest.class.getCanonicalName());
	private static final Logger HEALTH_LOGGER = LoggerFactory.getLogger(LOGGER.getName() + ".health");

	private static final String RESOURCE_NAME = "reverse-request";
	/**
	 * URI query parameter to specify reverse requests.
	 */
	private static final String URI_QUERY_OPTION_REQUEST = "req";
	/**
	 * URI query parameter to specify reverse resource.
	 */
	private static final String URI_QUERY_OPTION_RESOURCE = "res";
	/**
	 * Maximum number of requests.
	 */
	private static final int MAX_REQUESTS = 10000000;
	/**
	 * Overall requested requests.
	 */
	private final AtomicLong overallRequests = new AtomicLong();
	/**
	 * Overall sent requests.
	 */
	private final AtomicLong overallSentRequests = new AtomicLong();
	/**
	 * Overall pending requests.
	 */
	private final AtomicLong overallPendingRequests = new AtomicLong();

	/**
	 * Create reverse observation resource.
	 * 
	 * @param config network configuration to read HEALTH_STATUS_INTERVAL.
	 */
	public ReverseRequest(NetworkConfig config) {
		super(RESOURCE_NAME);
		getAttributes().setTitle("Reverse Request");
		getAttributes().addContentType(TEXT_PLAIN);
		getAttributes().addContentType(APPLICATION_OCTET_STREAM);
		int healthStatusInterval = config.getInt(NetworkConfig.Keys.HEALTH_STATUS_INTERVAL, 60); // seconds
		if (healthStatusInterval > 0 && HEALTH_LOGGER.isDebugEnabled()) {
			ExecutorsUtil.getScheduledExecutor().scheduleWithFixedDelay(new Runnable() {

				@Override
				public void run() {
					if (overallRequests.get() > 0) {
						HEALTH_LOGGER.debug("{} reverse-requests, {} sent, {} pending", overallRequests.get(),
								overallSentRequests.get(), overallPendingRequests.get());
					}
				}
			}, healthStatusInterval, healthStatusInterval, TimeUnit.SECONDS);
		}
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

		List<String> requestUriQuery = new ArrayList<>();
		List<String> uriQuery = request.getOptions().getUriQuery();
		Integer numberOfRequests = null;
		String resource = null;
		for (String query : uriQuery) {
			if (query.startsWith(URI_QUERY_OPTION_REQUEST + "=")) {
				String message = null;
				String req = query.substring(URI_QUERY_OPTION_REQUEST.length() + 1);
				try {
					numberOfRequests = Integer.parseInt(req);
					if (numberOfRequests < 0) {
						message = "URI-query-option " + query + " is negative number!";
					} else if (numberOfRequests > MAX_REQUESTS) {
						message = "URI-query-option " + query + " is too large (max. " + MAX_REQUESTS + ")!";
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
				requestUriQuery.add(query);
			}
		}

		if (resource != null && numberOfRequests != null) {
			long overall = overallRequests.addAndGet(numberOfRequests);
			overallPendingRequests.addAndGet(numberOfRequests);
			if (overallSentRequests.getAndIncrement() == 0) {
				LOGGER.info("start reverse requests!");
			}
			LOGGER.debug("{}", request);
			LOGGER.info("{}/{}: {} reverse requests, {} overall.", request.getSourceContext().getPeerAddress(),
					resource, numberOfRequests, overall);
			Endpoint endpoint = exchange.advanced().getEndpoint();
			exchange.respond(CHANGED);
			Request getRequest = Request.newGet();
			getRequest.getOptions().setUriPath(resource);
			for (String query : requestUriQuery) {
				getRequest.getOptions().addUriQuery(query);
			}
			getRequest.setDestinationContext(request.getSourceContext());
			getRequest.addMessageObserver(new GetRequestObserver(endpoint, getRequest, numberOfRequests));
			getRequest.send(endpoint);
		} else {
			exchange.respond(CONTENT, overallRequests.get() + " reverse-requests, " + overallSentRequests.get()
					+ " sent, " + overallPendingRequests.get() + " pending.", TEXT_PLAIN);
		}
	}

	private class GetRequestObserver extends MessageObserverAdapter {

		private Endpoint endpoint;
		private Request outgoingObserveRequest;
		private int count;

		public GetRequestObserver(Endpoint endpoint, Request outgoingObserveRequest, int count) {
			this.endpoint = endpoint;
			this.outgoingObserveRequest = outgoingObserveRequest;
			this.count = count;
		}

		@Override
		public void onResponse(final Response response) {
			if (response.isError()) {
				LOGGER.info("error: {}, pending: {}", response.getCode(), count);
				subtractPending(count);
			} else {
				--count;
				if (count > 0) {
					LOGGER.trace("send next request");
					overallSentRequests.incrementAndGet();
					Request getRequest = Request.newGet();
					getRequest.setOptions(outgoingObserveRequest.getOptions());
					getRequest.setDestinationContext(outgoingObserveRequest.getDestinationContext());
					getRequest.addMessageObserver(this);
					getRequest.send(endpoint);
				} else {
					LOGGER.trace("sent requests ready!");
				}
				subtractPending(1);
			}
		}

		@Override
		protected void failed() {
			LOGGER.info("get request failed! MID {}, pending: {}", outgoingObserveRequest.getMID(), count);
			subtractPending(count);
		}

		private void subtractPending(int count) {
			if (overallPendingRequests.addAndGet(-count) <= 0) {
				LOGGER.info("sent all requests, ready!");
			}
		}
	}

}
