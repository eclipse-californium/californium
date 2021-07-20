/*******************************************************************************
 * Copyright (c) 2015, 2017 Wireless Networks Group, UPC Barcelona, i2CAT and others.
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
 *    August Betzler    – CoCoA implementation
 *    Matthias Kovatsch - Embedding of CoCoA in Californium
 *    Achim Kraus (Bosch Software Innovations GmbH) - change lower()/upper() back to super
 *                                                    to ensure, that ReliabilityLayer
 *                                                    is processed.
 *    Achim Kraus (Bosch Software Innovations GmbH) - introduce updateRetransmissionTimeout()
 *                                                    issue #305
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/

package org.eclipse.californium.core.network.stack;

import java.net.InetSocketAddress;
import java.util.Queue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.config.CoapConfig.CongestionControlMode;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.stack.RemoteEndpoint.RtoType;
import org.eclipse.californium.core.network.stack.congestioncontrol.BasicRto;
import org.eclipse.californium.core.network.stack.congestioncontrol.Cocoa;
import org.eclipse.californium.core.network.stack.congestioncontrol.CongestionStatisticLogger;
import org.eclipse.californium.core.network.stack.congestioncontrol.LinuxRto;
import org.eclipse.californium.core.network.stack.congestioncontrol.PeakhopperRto;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;

/**
 * The optional Congestion Control (CC) Layer for the Californium CoAP
 * implementation provides the methods for advanced congestion control
 * mechanisms. The RTO calculations and other mechanisms are implemented in the
 * correspondent child classes and child classes of {@link RemoteEndpoint}.
 * 
 * Congestion Control affects basically two topics:
 * 
 * <ul>
 * <li>throttle the messages send to other peers</li>
 * <li>adapt the default RTO according the recent RTTs</li>
 * </ul>
 * 
 * <h2>Throttle the messages send to other peers</h2>
 * 
 * A peer sends:
 * 
 * <dl>
 * <dt>ACK (empty)/RST</dt>
 * <dd>Small messages to stop retransmissions of the other peer.</dd>
 * <dt>ACK (piggybacked)</dt>
 * <dd>Response Piggybacked.</dd>
 * <dt>Response (separate)</dt>
 * <dd>Response.</dd>
 * <dt>Response (Notify)</dt>
 * <dd>Multiple responses.</dd>
 * <dt>Response (Multicast)</dt>
 * <dd>Expected multiple responses.</dd>
 * <dt>Requests</dt>
 * <dd>Requests.</dd>
 * <dt>Requests (multicast)</dt>
 * <dd>Requests, expecting multiple responses</dd>
 * <dt>Requests (blockwise)</dt>
 * <dd>Multiple requests.</dd>
 * </dl>
 * 
 * To obey a define priority and somehow the original order seem to be
 * undefined.
 * 
 * The current, still experimental implementation, send the ACK/RST immediately
 * without applying throttling. The same applies to NON-response, if these
 * responses are no notifies. NSTART rules are then applied to CON-Responses
 * until the transmission is acknowledged. And to request until the response is
 * received. Notifies are throttled using a timer.
 * 
 * <h2>Adapt the default RTO according the recent RTTs</h2>
 * 
 * Currently following algorithms are implemented:
 * 
 * <dl>
 * <dt>BASICRTO</dt>
 * <dd>Use previously measured RTT and multiply it by 1.5 to calculate the RTO
 * for the next transmission.</dd>
 * <dt>LINUXRTO</dt>
 * <dd>The Linux RTO calculation mechanism.</dd>
 * <dt>PEAKHOPPERRTO</dt>
 * <dd>The Peakhopper RTO calculation mechanism (PH-RTO).</dd>
 * <dt>COCOA</dt>
 * <dd>CoCoA algorithm as defined in draft-bormann-cocoa-03.</dd>
 * <dt>COCOASTRONG</dt>
 * <dd>CoCoA but only with the strong estimator.</dd>
 * </dl>
 * 
 * Additionally, the mean value of a small history of RTO values is used.
 * 
 * All seems to be experimental and may result in different performance.
 */
public abstract class CongestionControlLayer extends ReliabilityLayer {

	// An upper limit for the queue size of confirmables
	// and non-confirmables (separate queues)
	private final static int EXCHANGELIMIT = 50;

	private final static int MIN_RTO = 500;
	private final static int MAX_RTO = 60000;

	/** The map of remote endpoints */
	private LeastRecentlyUsedCache<InetSocketAddress, RemoteEndpoint> remoteEndpoints;

	/** The configuration */
	protected final Configuration config;

	/**
	 * The logging tag.
	 */
	protected final String tag;

	// In CoAP, dithering is applied to the initial RTO of a transmission;
	// set to true to apply dithering
	private boolean appliesDithering;
	/**
	 * Statistic logger for congestion.
	 */
	private CongestionStatisticLogger statistic;

	/**
	 * Constructs a new congestion control layer.
	 * 
	 * @param tag logging tag
	 * @param config the configuration
	 * @since 3.0 (changed parameter to Configuration)
	 */
	public CongestionControlLayer(String tag, Configuration config) {
		super(config);
		this.tag = tag;
		this.config = config;
		this.remoteEndpoints = new LeastRecentlyUsedCache<>(config.get(CoapConfig.MAX_ACTIVE_PEERS),
				config.get(CoapConfig.MAX_PEER_INACTIVITY_PERIOD, TimeUnit.SECONDS));
		this.remoteEndpoints.setEvictingOnReadAccess(false);
		setDithering(false);
	}

	@Override
	public void start() {
		statistic = new CongestionStatisticLogger(tag, 5000, TimeUnit.MILLISECONDS, executor);
		statistic.start();
	}

	@Override
	public void destroy() {
		CongestionStatisticLogger statistic = this.statistic;
		if (statistic != null) {
			if (statistic.stop()) {
				statistic.dump();
			}
			this.statistic = null;
		}
	}

	/**
	 * Create new, algorithm specific remote endpoint.
	 * 
	 * @param remoteSocketAddress peer to create the endpoint for.
	 * @return create endpoint.
	 */
	protected abstract RemoteEndpoint createRemoteEndpoint(InetSocketAddress remoteSocketAddress);

	/**
	 * Get remote endpoint.
	 * 
	 * Create endpoint, if not available.
	 * 
	 * @param exchange to get the endpoint for
	 * @return endpoint for exchange.
	 * @see #createRemoteEndpoint(InetSocketAddress)
	 */
	protected RemoteEndpoint getRemoteEndpoint(Exchange exchange) {
		Message message;
		if (exchange.isOfLocalOrigin()) {
			message = exchange.getCurrentRequest();
		} else {
			message = exchange.getCurrentResponse();
		}
		InetSocketAddress remoteSocketAddress = message.getDestinationContext().getPeerAddress();
		synchronized (remoteEndpoints) {
			RemoteEndpoint remoteEndpoint = remoteEndpoints.get(remoteSocketAddress);
			if (remoteEndpoint == null) {
				remoteEndpoint = createRemoteEndpoint(remoteSocketAddress);
				remoteEndpoints.put(remoteSocketAddress, remoteEndpoint);
			}
			return remoteEndpoint;
		}
	}

	/**
	 * Check, if dithering is to be applied.
	 * 
	 * @return {@code true}, if dithering is applied for initial timeout value,
	 *         {@code false}, otherwise.
	 */
	public boolean appliesDithering() {
		return appliesDithering;
	}

	/**
	 * Enable or disable dithering.
	 * 
	 * @param mode {@code true}, if dithering is enabled, {@code false},
	 *            otherwise.
	 */
	public void setDithering(boolean mode) {
		this.appliesDithering = mode;
	}

	/**
	 * Gets state (Strong/Weak/NoneValidRTT) for this exchange
	 * 
	 * @param exchange the exchange
	 * @return the estimator ID
	 */
	public RtoType getExchangeEstimatorState(Exchange exchange) {
		int failed = exchange.getFailedTransmissionCount();
		switch (failed) {
		case 0:
			return RtoType.STRONG;
		case 1:
		case 2:
			return RtoType.WEAK;
		default:
			return RtoType.NONE;
		}
	}

	/**
	 * Process response.
	 * 
	 * @param endpoint endpoint to send response to
	 * @param exchange exchange of response
	 * @param response the response
	 * @return {@code true}, to send response immediately, {@code false}, if the
	 *         response is postponed and put into a queue.
	 */
	private boolean processResponse(RemoteEndpoint endpoint, Exchange exchange, Response response) {
		Type messageType = response.getType();
		if (!response.isNotification()) {
			if (messageType == Type.CON) {
				return checkNSTART(endpoint, exchange);
			} else {
				return true;
			}
		}
		// Check, if there's space in the notifies queue
		int size;
		boolean start = false;
		Queue<PostponedExchange> queue = endpoint.getNotifyQueue();
		synchronized (endpoint) {
			PostponedExchange postponedExchange = new PostponedExchange(exchange, response);
			queue.remove(postponedExchange);
			size = queue.size();
			if (size < EXCHANGELIMIT) {
				queue.add(postponedExchange);
				// Check if notifies are already processed
				// if not, start bucket task
				start = endpoint.startProcessingNotifies();
			}
		}
		if (size >= EXCHANGELIMIT) {
			LOGGER.debug("{}drop outgoing notify, queue full {}", tag, size);
		} else {
			if (start) {
				executor.execute(new BucketTask(endpoint));
			}
		}
		return false;
	}

	/**
	 * Check NSTART limit.
	 * 
	 * @param endpoint endpoint to check nstart.
	 * @param exchange exchange to check.
	 * @return {@code true}, to send the exchange immediately, {@code false}, if
	 *         the exchange is postponed and put into a queue.
	 */
	private boolean checkNSTART(RemoteEndpoint endpoint, Exchange exchange) {
		boolean send = false;
		boolean queued = false;
		Type type;
		String messageType;
		Queue<Exchange> queue;
		if (exchange.isOfLocalOrigin()) {
			messageType = "req.-";
			type = exchange.getCurrentRequest().getType();
			queue = endpoint.getRequestQueue();
		} else {
			messageType = "resp.-";
			type = exchange.getCurrentResponse().getType();
			queue = endpoint.getResponseQueue();
		}
		int size;
		synchronized (endpoint) {
			size = queue.size();
			if (endpoint.registerExchange(exchange)) {
				send = true;
			} else if (size < EXCHANGELIMIT) {
				// Check if the queue limit for exchanges is already reached
				// Queue exchange in the CON-Queue
				queue.add(exchange);
				// System.out.println("Added exchange to the queue (NSTART
				// limit reached)");
				queued = true;
			}
		}
		if (send) {
			Message message;
			if (exchange.isOfLocalOrigin()) {
				// it's a request
				message = exchange.getCurrentRequest();
			} else {
				// it's a response
				message = exchange.getCurrentResponse();
			}
			message.addMessageObserver(new TimeoutTask(endpoint, exchange));
			LOGGER.trace("{}send {}{}", tag, messageType, type);
			if (statistic != null) {
				statistic.sendRequest();
			}
			return true;
		} else if (queued) {
			if (statistic != null) {
				statistic.queueRequest();
			}
		} else {
			LOGGER.debug("{}drop {}{}, queue full {}", tag, messageType, type, size);
		}
		return false;
	}

	/**
	 * Process RTT.
	 * 
	 * @param exchange exchange to process
	 * @see RemoteEndpoint#processRttMeasurement(RtoType, long)
	 */
	private void processRttMeasurement(Exchange exchange) {
		RemoteEndpoint endpoint = getRemoteEndpoint(exchange);
		Response response = exchange.getCurrentResponse();
		if (response != null) {
			Long rttNanos = response.getTransmissionRttNanos();
			if (rttNanos != null) {
				RtoType rtoType = getExchangeEstimatorState(exchange);
				if (rtoType != RtoType.NONE) {
					long measuredRTT = Math.max(TimeUnit.NANOSECONDS.toMillis(rttNanos), 1);
					// process the RTT measurement
					endpoint.processRttMeasurement(rtoType, measuredRTT);
				}
			}
		}
		nextQueuedExchange(endpoint, exchange);
	}

	/**
	 * Calculates the Backoff Factor for the retransmissions. By default this is
	 * a binary backoff (= 2)
	 * 
	 * @param rto the initial RTO value
	 * @param scale scale factor for backoff
	 * @return the new VBF
	 */
	protected float calculateVBF(long rto, float scale) {
		return scale;
	}

	/**
	 * Get next exchange from queues and register it for sending.
	 * 
	 * @param endpoint endpoint to send message to
	 * @param removeExchange previous excahnge to remove
	 */
	private void nextQueuedExchange(final RemoteEndpoint endpoint, Exchange removeExchange) {
		Exchange nextExchange = null;
		synchronized (endpoint) {
			if (endpoint.removeExchange(removeExchange)) {
				nextExchange = endpoint.getResponseQueue().poll();
				if (nextExchange == null) {
					nextExchange = endpoint.getRequestQueue().poll();
				}
				if (nextExchange != null) {
					endpoint.registerExchange(nextExchange);
				}
			}
		}
		if (nextExchange != null) {
			statistic.dequeueRequest();
			final Exchange exchange = nextExchange;
			Type type;
			String messageType;
			int size;
			if (exchange.isOfLocalOrigin()) {
				messageType = "req.-";
				type = exchange.getCurrentRequest().getType();
				size = endpoint.getRequestQueue().size();
			} else {
				messageType = "resp.-";
				type = exchange.getCurrentResponse().getType();
				size = endpoint.getResponseQueue().size();
			}
			LOGGER.trace("{}send from queue {}{}, queue left {}", tag, messageType, type, size);
			exchange.execute(new Runnable() {

				@Override
				public void run() {
					if (exchange.isComplete()) {
						// may be completed in the meantime, e.g. blockwise
						nextQueuedExchange(endpoint, exchange);
						return;
					}
					// We have some exchanges that need to be processed;
					// is it a response or a request?
					if (exchange.isOfLocalOrigin()) {
						// it's a request
						sendRequest(exchange, exchange.getCurrentRequest());
					} else {
						// it's a response
						sendResponse(exchange, exchange.getCurrentResponse());
					}
				}
			});
		}
	}

	/**
	 * Forward the request to the lower layer.
	 * 
	 * @param exchange the exchange
	 * @param request the current request
	 */
	@Override
	public void sendRequest(Exchange exchange, Request request) {
		if (exchange.getFailedTransmissionCount() > 0) {
			LOGGER.warn("{}retransmission in sendRequest", tag, new Throwable("retransmission"));
			return;
		}
		// process ReliabilityLayer
		prepareRequest(exchange, request);
		RemoteEndpoint endpoint = getRemoteEndpoint(exchange);
		if (checkNSTART(endpoint, exchange)) {
			endpoint.checkAging();
			LOGGER.debug("{}send request", tag);
			if (!endpoint.inFlightExchange(exchange)) {
				LOGGER.warn("{}unregistered request", tag, new Throwable("unregistered request"));
			}
			lower().sendRequest(exchange, request);
		}
	}

	/**
	 * Forward the response to the lower layer.
	 * 
	 * @param exchange the exchange
	 * @param response the current response
	 */
	@Override
	public void sendResponse(Exchange exchange, Response response) {
		RemoteEndpoint endpoint = getRemoteEndpoint(exchange);
		// process ReliabilityLayer
		prepareResponse(exchange, response);
		// Check if exchange is already running into a retransmission; if so,
		// don't call processMessage, since this is a retransmission
		if (exchange.getFailedTransmissionCount() > 0) {
			if (response.isNotification()) {
				lower().sendResponse(exchange, response);
			} else {
				LOGGER.warn("{}retransmission in sendResponse", tag, new Throwable("retransmission"));
			}
		} else if (processResponse(endpoint, exchange, response)) {
			endpoint.checkAging();
			lower().sendResponse(exchange, response);
		}
	}

	@Override
	protected void updateRetransmissionTimeout(Exchange exchange,
			ReliabilityLayerParameters reliabilityLayerParameters) {
		int timeout;
		int maxTimeout = Math.min(reliabilityLayerParameters.getMaxAckTimeout(), MAX_RTO);

		RemoteEndpoint remoteEndpoint = getRemoteEndpoint(exchange);
		if (exchange.getFailedTransmissionCount() == 0) {
			if (defaultReliabilityLayerParameters == reliabilityLayerParameters) {
				timeout = (int) remoteEndpoint.getRTO();
			} else {
				// message specific parameter =>
				// use message specific ack timeout
				timeout = reliabilityLayerParameters.getAckTimeout();
			}
			if (appliesDithering()) {
				timeout = getRandomTimeout(timeout, reliabilityLayerParameters.getAckRandomFactor());
			}
			timeout = Math.max(MIN_RTO, timeout);
			timeout = Math.min(maxTimeout, timeout);
			float scale = calculateVBF(timeout, reliabilityLayerParameters.getAckTimeoutScale());
			exchange.setTimeoutScale(scale);
		} else {
			timeout = (int) (exchange.getTimeoutScale() * exchange.getCurrentTimeout());
			timeout = Math.min(maxTimeout, timeout);
		}
		exchange.setCurrentTimeout(timeout);
	}

	@Override
	public void receiveResponse(Exchange exchange, Response response) {
		LOGGER.debug("{}receive response", tag);
		if (processResponse(exchange, response)) {
			processRttMeasurement(exchange);
			if (statistic != null) {
				statistic.receiveResponse(response);
			}
			upper().receiveResponse(exchange, response);
		}
	}

	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		if (processEmptyMessage(exchange, message)) {
			processRttMeasurement(exchange);
			upper().receiveEmptyMessage(exchange, message);
		}
	}

	/*
	 * This Thread is used to apply rate control to non-confirmables by polling
	 * them from the queue and scheduling the task to run again later.
	 */
	private class BucketTask implements Runnable {

		final AtomicInteger count = new AtomicInteger();
		final RemoteEndpoint endpoint;

		public BucketTask(final RemoteEndpoint queue) {
			endpoint = queue;
		}

		@Override
		public void run() {
			int size = 0;
			final PostponedExchange exchange;
			synchronized (endpoint) {
				exchange = endpoint.getNotifyQueue().peek();
				if (exchange == null) {
					endpoint.stopProcessingNotifies();
				} else {
					count.incrementAndGet();
					size = endpoint.getNotifyQueue().size();
				}
			}
			if (exchange != null) {
				final long rto = endpoint.getRTO();
				LOGGER.trace("{}send notify from queue, left {}, next {} ms", tag, size, rto);
				exchange.exchange.execute(new Runnable() {

					@Override
					public void run() {
						long time = 0;
						try {
							synchronized (endpoint) {
								if (endpoint.getNotifyQueue().peek() != exchange) {
									return;
								}
								endpoint.getNotifyQueue().remove();
							}
							ObserveRelation relation = exchange.exchange.getRelation();
							if (relation != null && !relation.isCanceled()) {
								Response response = exchange.exchange.getCurrentResponse();
								if (exchange.message != response) {
									if (response.isNotification()) {
										LOGGER.warn("{} notify changed!", tag);
									} else {
										LOGGER.warn("{} notification finished!", tag);
									}
									return;
								}
								if (!exchange.exchange.isComplete() && !response.isCanceled()) {
									CongestionControlLayer.super.sendResponse(exchange.exchange, response);
									time = rto;
								}
							}
						} finally {
							if (time > 0) {
								executor.schedule(BucketTask.this, time, TimeUnit.MILLISECONDS);
							} else {
								executor.execute(BucketTask.this);
							}
						}
					}
				});
			} else {
				int jobs = count.getAndSet(0);
				LOGGER.debug("{}queue for outgoing notify stopped after {} jobs!", tag, jobs);
			}
		}
	}

	/*
	 * Task that deletes old exchanges from the remote endpoint list
	 */
	private class TimeoutTask extends MessageObserverAdapter {

		final RemoteEndpoint endpoint;
		final Exchange exchange;

		public TimeoutTask(final RemoteEndpoint endpoint, final Exchange exchange) {
			this.endpoint = endpoint;
			this.exchange = exchange;
		}

		@Override
		public void onTimeout() {
			nextQueuedExchange(endpoint, exchange);
		}
	}

	public static class PostponedExchange {

		private final Exchange exchange;
		private final Message message;

		PostponedExchange(Exchange exchange, Message message) {
			this.exchange = exchange;
			this.message = message;
		}

		@Override
		public int hashCode() {
			return exchange.hashCode();
		}

		@Override
		public boolean equals(Object obj) {
			if (obj instanceof PostponedExchange) {
				return exchange.equals(((PostponedExchange) obj).exchange);
			}
			return false;
		}
	}

	/**
	 * Create reliability layer based on the configuration.
	 * 
	 * @param tag logging tag
	 * @param config configuration
	 * @return reliability layer
	 * @since 3.0
	 */
	public static ReliabilityLayer newImplementation(String tag, Configuration config) {
		ReliabilityLayer layer = null;
		CongestionControlMode mode = config.get(CoapConfig.CONGESTION_CONTROL_ALGORITHM);
		switch (mode) {
		case COCOA:
			layer = new Cocoa(tag, config, false);
			break;
		case COCOA_STRONG:
			layer = new Cocoa(tag, config, true);
			break;
		case BASIC_RTO:
			layer = new BasicRto(tag, config);
			break;
		case LINUX_RTO:
			layer = new LinuxRto(tag, config);
			break;
		case PEAKHOPPER_RTO:
			layer = new PeakhopperRto(tag, config);
			break;
		case NULL:
			layer = new ReliabilityLayer(config);
			break;
		}
		if (layer != null) {
			if (mode != CongestionControlMode.NULL) {
				LOGGER.info("Enabling congestion control: {}", layer.getClass().getSimpleName());
			}
			return layer;
		}
		throw new IllegalArgumentException("Unsupported " + CoapConfig.CONGESTION_CONTROL_ALGORITHM.getKey());
	}
}
