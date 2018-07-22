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
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Future;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reverse observe resource.
 * 
 * NOT intended to be used at californium-sandbox!
 */
public class Feed extends CoapResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(Feed.class.getCanonicalName());
	/**
	 * Resource name.
	 */
	private static final String RESOURCE_NAME = "feed";
	/**
	 * URI query parameter to specify response length.
	 */
	private static final String URI_QUERY_OPTION_RESPONSE_LENGTH = "rlen";
	/**
	 * Default interval for notifies in milliseconds.
	 */
	public static final int DEFAULT_FEED_INTERVAL_IN_MILLIS = 100;
	/**
	 * Minimum timeout for notifies complete in milliseconds.
	 */
	public static final int DEFAULT_TIMEOUT_IN_MILLIS = 2000;
	/**
	 * Random generator for interval.
	 */
	private static final Random random = new Random(1234);
	/**
	 * Default response.
	 */
	private final String payload;
	/**
	 * Simple ID to distinguish the coap servers.
	 */
	private final int id;
	/**
	 * Maximum message size.
	 */
	private final int maxResourceSize;
	/**
	 * Minimum change interval in milliseconds.
	 */
	private final int intervalMin;
	/**
	 * Maximum change interval in milliseconds.
	 */
	private final int intervalMax;
	/**
	 * Counter for gets/notifies.
	 */
	private final CountDownLatch counter;
	/**
	 * Counter for gets/notifies, which are not reported to complete nor fail.
	 */
	private final AtomicLong timeouts;
	/**
	 * Lock for change schedules. {@code true} if schedule, {@code false}, if
	 * not.
	 */
	private final AtomicBoolean changeScheduled = new AtomicBoolean();
	/**
	 * Change job for scheduling.
	 */
	private final Runnable change = new Runnable() {

		@Override
		public void run() {
			changeScheduled.set(false);
			LOGGER.info("client[{}] feed change triggered, {} observers", id, getObserverCount());
			changed();
		}
	};
	/**
	 * Executor to schedule {@link #change} jobs.
	 */
	private final ScheduledExecutorService executorService;

	public Feed(CoAP.Type type, int id, int maxResourceSize, int intervalMin, int intervalMax,
			ScheduledExecutorService executorService, CountDownLatch counter, AtomicLong timeouts) {
		super(RESOURCE_NAME + "-" + type);
		this.id = id;
		this.maxResourceSize = maxResourceSize;
		this.intervalMin = intervalMin;
		this.intervalMax = intervalMax;
		this.counter = counter;
		this.timeouts = timeouts;
		this.executorService = executorService;
		this.payload = "hello " + id + " feed";
		setObservable(true);
		setObserveType(type);
		getAttributes().setTitle("Feed - " + type);
		getAttributes().addContentType(TEXT_PLAIN);
	}

	@Override
	public void handleGET(CoapExchange exchange) {
		// get request to read out details
		Request request = exchange.advanced().getRequest();

		int accept = request.getOptions().getAccept();
		if (accept != UNDEFINED && accept != TEXT_PLAIN) {
			exchange.respond(NOT_ACCEPTABLE);
			return;
		}

		List<String> uriQuery = request.getOptions().getUriQuery();
		int length = 0;
		for (String query : uriQuery) {
			String message = null;
			if (query.startsWith(URI_QUERY_OPTION_RESPONSE_LENGTH + "=")) {
				String rlen = query.substring(URI_QUERY_OPTION_RESPONSE_LENGTH.length() + 1);
				try {
					length = Integer.parseInt(rlen);
					if (length < 0) {
						message = "URI-query-option " + query + " is negative number!";
					} else if (length > maxResourceSize && maxResourceSize > 0) {
						message = "URI-query-option " + query + " is too large (max. " + maxResourceSize + ")!";
					}
				} catch (NumberFormatException ex) {
					message = "URI-query-option " + query + " is no number!";
				}
			} else {
				message = "URI-query-option " + query + " is not supported!";
			}
			if (message != null) {
				Response response = Response.createResponse(request, BAD_OPTION);
				response.setPayload(message);
				exchange.respond(response);
				return;
			}
		}

		long count;
		synchronized (counter) {
			counter.countDown();
			count = counter.getCount();
		}
		// Changing payload on every GET is no good idea,
		// but helps to debug blockwise notifies :-)
		byte[] responsePayload = (payload + "-" + count).getBytes();
		if (length > 0) {
			byte[] payload = responsePayload;
			responsePayload = Arrays.copyOf(responsePayload, length);
			if (length > payload.length) {
				Arrays.fill(responsePayload, payload.length, length, (byte) '*');
			}
		}

		Response response = Response.createResponse(request, CONTENT);
		response.setToken(request.getToken());
		response.setPayload(responsePayload);
		response.getOptions().setContentFormat(TEXT_PLAIN);
		if (request.isObserve()) {
			int observer = getObserverCount();
			if (changeScheduled.compareAndSet(false, true)) {
				int timeout;
				final int interval;
				if (intervalMin < intervalMax) {
					float r = random.nextFloat();
					interval = (int) ((r * r * r) * (intervalMax - intervalMin)) + intervalMin;
					timeout = intervalMax;
				} else {
					interval = intervalMin;
					timeout = intervalMin;
				}
				if (interval <= 0) {
					if (timeout < DEFAULT_TIMEOUT_IN_MILLIS) {
						timeout = DEFAULT_TIMEOUT_IN_MILLIS;
					}
					LOGGER.info("client[{}] {} observer, wait for response {} completed.", id, observer,
							response.getToken());
					final AtomicBoolean scheduled = new AtomicBoolean();
					final Future<?> timeoutFuture = executorService.schedule(new Runnable() {

						@Override
						public void run() {
							if (scheduled.compareAndSet(false, true)) {
								LOGGER.info(
										"client[{}] response didn't complete in time, next change in {} ms, {} observer.",
										id, -interval, getObserverCount());
								timeouts.incrementAndGet();
								executorService.schedule(change, -interval, TimeUnit.MILLISECONDS);
							}
						}
					}, timeout, TimeUnit.MILLISECONDS);

					response.addMessageObserver(new MessageObserverAdapter() {

						@Override
						public void onComplete() {
							if (scheduled.compareAndSet(false, true)) {
								timeoutFuture.cancel(false);
								LOGGER.info("client[{}] response complete, next change in {} ms, {} observer.", id,
										-interval, getObserverCount());
								executorService.schedule(change, -interval, TimeUnit.MILLISECONDS);
							}
						}

						@Override
						protected void failed() {
							if (scheduled.compareAndSet(false, true)) {
								timeoutFuture.cancel(false);
								LOGGER.info("client[{}] response failed, next change in {} ms, {} observer.", id,
										-interval, getObserverCount());
								executorService.schedule(change, -interval, TimeUnit.MILLISECONDS);
							}
						}

					});
				} else {
					LOGGER.info("client[{}] next change in {} ms, {} observer.", id, interval, observer);
					executorService.schedule(change, interval, TimeUnit.MILLISECONDS);
				}
			} else {
				LOGGER.info("client[{}] pending change, {} observer, send {}!", id, observer, response.getToken());
			}
		} else {
			LOGGER.info("client[{}] no observe {}!", id, request);
		}
		exchange.respond(response);
	}
}
