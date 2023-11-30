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
 *    Achim Kraus (Bosch Software Innovations GmbH) - report response on completion
 *                                                    instead start sending.
 *                                                    Keeps client longer running.
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
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.UriQueryParameter;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.util.FilteredLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Reverse observe resource.
 * 
 * NOT intended to be used at californium-sandbox!
 */
public class Feed extends CoapResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(Feed.class);

	private static final FilteredLogger ERROR_FILTER = new FilteredLogger(LOGGER.getName(), 3, TimeUnit.SECONDS.toNanos(10));

	/**
	 * Resource name.
	 */
	private static final String RESOURCE_NAME = "feed";
	/**
	 * URI query parameter to specify response length.
	 */
	private static final String URI_QUERY_OPTION_RESPONSE_LENGTH = "rlen";
	/**
	 * URI query parameter to specify ack and separate response.
	 */
	private static final String URI_QUERY_OPTION_ACK = "ack";
	/**
	 * Supported query parameter.
	 * 
	 * @since 3.2
	 */
	private static final List<String> SUPPORTED = Arrays.asList(URI_QUERY_OPTION_RESPONSE_LENGTH, URI_QUERY_OPTION_ACK);
	/**
	 * Default interval for notifies in milliseconds.
	 */
	public static final int DEFAULT_FEED_INTERVAL_IN_MILLIS = 100;
	/**
	 * Default interval for notifies in milliseconds.
	 */
	public static final int MIN_FEED_INTERVAL_IN_MILLIS = 20;
	/**
	 * Minimum timeout for notifies complete in milliseconds.
	 */
	public static final int DEFAULT_TIMEOUT_IN_MILLIS = 5000;
	/**
	 * Random generator for interval.
	 */
	private static final Random random = new Random(1234);
	/**
	 * Counter for started gets/notifies.
	 */
	private static final AtomicLong started = new AtomicLong();
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
	 * 
	 */
	private final CountDownLatch counterDone;
	/**
	 * Counter for finished gets/notifies.
	 */
	private final AtomicLong counter;
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
	/**
	 * Indicate to stop sending responses.
	 */
	private final AtomicBoolean stop;

	public Feed(CoAP.Type type, int id, int maxResourceSize, int intervalMin, int intervalMax,
			ScheduledExecutorService executorService, CountDownLatch counterDone, AtomicLong counter, AtomicLong timeouts, AtomicBoolean stop) {
		super(RESOURCE_NAME + "-" + type);
		this.id = id;
		this.maxResourceSize = maxResourceSize;
		this.intervalMin = intervalMin;
		this.intervalMax = intervalMax;
		this.counterDone = counterDone;
		this.counter = counter;
		this.timeouts = timeouts;
		this.executorService = executorService;
		this.stop = stop;
		this.payload = "hello " + id + " feed";
		setObservable(true);
		setObserveType(type);
		getAttributes().setTitle("Feed - " + type);
		getAttributes().addContentType(TEXT_PLAIN);
	}

	@Override
	public void handleGET(CoapExchange exchange) {
		if (stop.get()) {
			return;
		}
		// get request to read out details
		Request request = exchange.advanced().getRequest();

		int accept = request.getOptions().getAccept();
		if (accept != UNDEFINED && accept != TEXT_PLAIN) {
			exchange.respond(NOT_ACCEPTABLE);
			return;
		}

		boolean ack = false;
		int length = 0;
		try {
			UriQueryParameter helper = request.getOptions().getUriQueryParameter(SUPPORTED);
			ack = helper.hasParameter(URI_QUERY_OPTION_ACK);
			length = helper.getArgumentAsInteger(URI_QUERY_OPTION_RESPONSE_LENGTH, 0, 0, maxResourceSize);
		} catch (IllegalArgumentException ex) {
			exchange.respond(BAD_OPTION, ex.getMessage());
			return;
		}

		long count = started.incrementAndGet();

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

		try {
			int interval = 0;
			int timeout = 0;
			Response response = Response.createResponse(request, CONTENT);
			response.setToken(request.getToken());
			response.setPayload(responsePayload);
			response.getOptions().setContentFormat(TEXT_PLAIN);
			if (request.isObserve()) {
				int observer = getObserverCount();
				if (changeScheduled.compareAndSet(false, true)) {
					if (intervalMin < intervalMax) {
						// adapt linear distribution into cubic distribution
						// scale from [0...1.0) to [-1.0...1.0)
						float r = (random.nextFloat() * 2.0F) - 1.0F;
						// scale r^3 [-1.0...1.0) back to [0...1.0)
						r = ((r * r * r) + 1.0F) / 2.0F;
						interval = (int) (r * (intervalMax - intervalMin)) + intervalMin;
						timeout = intervalMax;
					} else {
						interval = intervalMin;
						timeout = intervalMin;
					}
					if (interval <= 0) {
						timeout = Math.max(DEFAULT_TIMEOUT_IN_MILLIS, timeout);
						LOGGER.info("client[{}] {} observer, wait for response {} completed.", id, observer,
								response.getToken());
					} else {
						timeout = 0;
						interval = Math.max(MIN_FEED_INTERVAL_IN_MILLIS, interval);
						LOGGER.info("client[{}] next change in {} ms, {} observer.", id, interval, observer);
					}
				} else {
					LOGGER.info("client[{}] pending change, {} observer, send {}!", id, observer, response.getToken());
				}
			} else {
				LOGGER.info("client[{}] no observe {}!", id, request);
				if (ack) {
					exchange.accept();
				}
			}
			response.addMessageObserver(new MessageCompletionObserver(timeout, interval));
			response.addMessageObserver(new SendErrorObserver(response));
			exchange.respond(response);
			if (counter.decrementAndGet() <= 0) {
				counterDone.countDown();
			}
		} catch (RejectedExecutionException ex) {
			LOGGER.debug("client[{}] stopped execution.", id);
			return;
		}
	}

	private class MessageCompletionObserver extends MessageObserverAdapter implements Runnable {

		private final Future<?> timeoutJob;
		private final AtomicBoolean completed = new AtomicBoolean();
		/**
		 * Delay of next change in milliseconds. Values larger than 0 millis are
		 * scheduled on completion of the transfer. 0, for execute
		 */
		private final int interval;

		private MessageCompletionObserver(int timeout, int interval) {
			if (0 < timeout) {
				this.timeoutJob = executorService.schedule(this, timeout, TimeUnit.MILLISECONDS);
			} else {
				this.timeoutJob = null;
			}
			this.interval = interval;
		}

		@Override
		public void onSent(boolean retransmission) {
			if (interval > 0 && !retransmission) {
				if (completed.compareAndSet(false, true)) {
					executorService.schedule(change, interval, TimeUnit.MILLISECONDS);
				}
			}
		}

		@Override
		public void onCancel() {
			if (completed.compareAndSet(false, true)) {
				if (timeoutJob != null) {
					timeoutJob.cancel(false);
				}
			}
		}

		@Override
		public void onTransferComplete() {
			if (completed.compareAndSet(false, true)) {
				next("completed", false);
			}
		}

		@Override
		protected void failed() {
			if (completed.compareAndSet(false, true)) {
				next("failed", true);
			}
		}

		@Override
		public void run() {
			// timeout
			if (completed.compareAndSet(false, true) && !stop.get() && counter.get() > 0) {
				try {
					if (interval < 0) {
						LOGGER.info("client[{}] response didn't complete in time, next change in {} ms, {} observer.",
								id, -interval, getObserverCount());
						timeouts.incrementAndGet();
						executorService.schedule(change, -interval, TimeUnit.MILLISECONDS);
					} else if (interval == 0) {
						executorService.execute(change);
					}
				} catch (RejectedExecutionException ex) {
					LOGGER.debug("client[{}] stopped execution.", id);
				}
			}
		}

		private void next(String state, boolean failure) {
			if (timeoutJob != null) {
				timeoutJob.cancel(false);
			}
			if (!stop.get() && counter.get() > 0) {
				try {
					int time = failure ? Math.max(1000, -interval) : -interval;
					if (0 < time) {
						LOGGER.info("client[{}] response {}, next change in {} ms, {} observer.", id, state, time,
								getObserverCount());
						executorService.schedule(change, time, TimeUnit.MILLISECONDS);
					} else if (time == 0) {
						executorService.execute(change);
					} else {
						LOGGER.info("client[{}] response {}, {} observer.", id, state, getObserverCount());
					}
				} catch (RejectedExecutionException ex) {
					LOGGER.debug("client[{}] stopped execution.", id);
				}
			}
		}
	}

	private static class SendErrorObserver extends MessageObserverAdapter {

		private final Response response;

		private SendErrorObserver(Response response) {
			this.response = response;
		}

		@Override
		public void onSendError(Throwable error) {
			ERROR_FILTER.warn("send failed: {} {}", getMessage(error), response);
			super.onSendError(error);
		}

		@Override
		public void onResponseHandlingError(Throwable error) {
			ERROR_FILTER.warn("respond failed: {} {}", getMessage(error), response);
			super.onResponseHandlingError(error);
		}

		private String getMessage(Throwable error) {
			String message = error.getMessage();
			if (message == null) {
				message = error.getClass().getSimpleName();
			}
			return message;
		}
	}
}
