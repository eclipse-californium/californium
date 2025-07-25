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
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_OCTET_STREAM;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.eclipse.californium.core.CoapExchange;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.ResponseTimeout;
import org.eclipse.californium.core.coap.UriQueryParameter;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.exception.ConnectorException;
import org.eclipse.californium.elements.util.DatagramWriter;
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

	private static final Logger LOGGER = LoggerFactory.getLogger(ReverseRequest.class);
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
	 * Supported query parameter.
	 * 
	 * @since 3.2
	 */
	private static final List<String> SUPPORTED = Arrays.asList(URI_QUERY_OPTION_REQUEST, URI_QUERY_OPTION_RESOURCE);
	/**
	 * Maximum number of requests.
	 */
	private static final int MAX_REQUESTS = 10000000;
	/**
	 * Timeout for response in milliseconds.
	 */
	private static final int RESPONSE_TIMEOUT_MILLIS = 120000;
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
	 * Scheduler for request timeout.
	 */
	private final ScheduledExecutorService executor;

	/**
	 * Create reverse observation resource.
	 * 
	 * @param config configuration to read HEALTH_STATUS_INTERVAL.
	 */
	public ReverseRequest(Configuration config, ScheduledExecutorService executor) {
		super(RESOURCE_NAME);
		this.executor = executor;
		getAttributes().setTitle("Reverse Request");
		addSupportedContentFormats(TEXT_PLAIN, APPLICATION_OCTET_STREAM);
		long healthStatusInterval = config.get(SystemConfig.HEALTH_STATUS_INTERVAL, TimeUnit.MILLISECONDS);
		if (healthStatusInterval > 0 && HEALTH_LOGGER.isDebugEnabled()) {
			executor.scheduleWithFixedDelay(new Runnable() {

				@Override
				public void run() {
					if (overallRequests.get() > 0) {
						HEALTH_LOGGER.debug("{} reverse-requests, {} sent, {} pending", overallRequests.get(),
								overallSentRequests.get(), overallPendingRequests.get());
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
		List<String> requestUriQuery = new ArrayList<>();
		Integer numberOfRequests = null;
		String resource = null;
		try {
			UriQueryParameter helper = request.getOptions().getUriQueryParameter(SUPPORTED, requestUriQuery);
			if (helper.hasParameter(URI_QUERY_OPTION_REQUEST)) {
				numberOfRequests = helper.getArgumentAsInteger(URI_QUERY_OPTION_REQUEST, 1, 1, MAX_REQUESTS);
			}
			resource = helper.getArgument(URI_QUERY_OPTION_RESOURCE, null);
		} catch (IllegalArgumentException ex) {
			exchange.respond(BAD_OPTION, ex.getMessage());
			return;
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
			GetRequestObserver requestObserver = new GetRequestObserver(endpoint, getRequest, numberOfRequests);
			getRequest.addMessageObserver(requestObserver);
			getRequest.addMessageObserver(new ResponseTimeout(getRequest, RESPONSE_TIMEOUT_MILLIS, executor));
			getRequest.send(endpoint);
		} else if (accept != APPLICATION_OCTET_STREAM) {
			exchange.respond(CHANGED, overallRequests.get() + " reverse-requests, " + overallSentRequests.get()
					+ " sent, " + overallPendingRequests.get() + " pending.", TEXT_PLAIN);
		} else {
			DatagramWriter writer = new DatagramWriter(24);
			writer.writeLong(overallRequests.get(), 64);
			writer.writeLong(overallSentRequests.get(), 64);
			writer.writeLong(overallPendingRequests.get(), 64);
			exchange.respond(CHANGED, writer.toByteArray(), APPLICATION_OCTET_STREAM);
			writer.close();
		}
	}

	private class GetRequestObserver extends MessageObserverAdapter implements Runnable {

		private final Endpoint endpoint;
		private Request outgoingRequest;
		private int count;
		private boolean failureLogged;

		public GetRequestObserver(Endpoint endpoint, Request outgoingRequest, int count) {
			this.endpoint = endpoint;
			this.outgoingRequest = outgoingRequest;
			this.count = count;
		}

		@Override
		public void onResponse(final Response response) {
			if (response.isError()) {
				LOGGER.info("error: {} {}, pending: {}", outgoingRequest.getScheme(), response.getCode(), count);
				subtractPending(count);
			} else {
				--count;
				if (count > 0) {
					LOGGER.trace("send next request");
					overallSentRequests.incrementAndGet();
					Request getRequest = Request.newGet();
					getRequest.setOptions(outgoingRequest.getOptions());
					getRequest.setDestinationContext(outgoingRequest.getDestinationContext());
					outgoingRequest = getRequest;
					getRequest.addMessageObserver(this);
					getRequest.addMessageObserver(new ResponseTimeout(getRequest, RESPONSE_TIMEOUT_MILLIS, executor));
					getRequest.send(endpoint);
				} else {
					LOGGER.trace("sent requests ready!");
				}
				subtractPending(1);
			}
		}

		@Override
		public void onSendError(Throwable error) {
			if (error instanceof ConnectorException) {
				LOGGER.warn("reverse get request failed! {} MID {}, pending: {}", outgoingRequest.getScheme(),
						outgoingRequest.getMID(), count);
				failureLogged = true;
			}
			super.onSendError(error);
		}

		@Override
		protected void failed() {
			if (!failureLogged) {
				LOGGER.debug("reverse get request failed! {} MID {}, pending: {}", outgoingRequest.getScheme(),
						outgoingRequest.getMID(), count);
			}
			subtractPending(count);
		}

		private void subtractPending(int count) {
			if (overallPendingRequests.addAndGet(-count) <= 0) {
				LOGGER.info("sent all requests, ready!");
			}
		}

		@Override
		public void run() {
			outgoingRequest.cancel();
		}
	}

}
