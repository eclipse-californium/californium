/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Achim Kraus (Bosch Software Innovations GmbH) - use final for fields and adjust
 *                                                    thread safe random usage
 *    Achim Kraus (Bosch Software Innovations GmbH) - use synchronized to access exchange.
 *    Achim Kraus (Bosch Software Innovations GmbH) - start retransmission timer, when message
 *                                                    is reported as sent. introduce 
 *                                                    updateRetransmissionTimeout() for
 *                                                    supporting CongestionControlLayer
 *                                                    issue #305
 *    Achim Kraus (Bosch Software Innovations GmbH) - move Message.setTimedOut() into
 *                                                    Exchange.setTimedOut()
 *    Achim Kraus (Bosch Software Innovations GmbH) - correct timeout calculation
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - fix resend current response
 *    Achim Kraus (Bosch Software Innovations GmbH) - remove synchronization and use
 *                                                    striped exchange execution instead.
 *    Achim Kraus (Bosch Software Innovations GmbH) - replace striped executor
 *                                                    with serial executor
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.Random;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.EndpointContextUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The reliability layer. CON retransmission. ACK/RST processing.
 */
public class ReliabilityLayer extends AbstractLayer {

	/** The logger. */
	protected final static Logger LOGGER = LoggerFactory.getLogger(ReliabilityLayer.class);

	/** The random numbers generator for the back-off timer */
	private final Random rand = new Random();

	private final ReliabilityLayerParameters defaultReliabilityLayerParameters;

	private final AtomicInteger counter = new AtomicInteger();

	/**
	 * Constructs a new reliability layer. Changes to the configuration are
	 * observed and automatically applied.
	 * 
	 * @param config the configuration
	 */
	public ReliabilityLayer(NetworkConfig config) {
		defaultReliabilityLayerParameters = ReliabilityLayerParameters.builder().applyConfig(config).build();
		LOGGER.info("ReliabilityLayer uses ACK_TIMEOUT={}, ACK_RANDOM_FACTOR={}, and ACK_TIMEOUT_SCALE={} as default",
				defaultReliabilityLayerParameters.getAckTimeout(), defaultReliabilityLayerParameters.getAckRandomFactor(),
				defaultReliabilityLayerParameters.getAckTimeoutScale());
	}

	/**
	 * Schedules a retransmission for confirmable messages.
	 */
	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		LOGGER.debug("{} send request, failed transmissions: {}", exchange, exchange.getFailedTransmissionCount());

		if (request.getType() == null) {
			request.setType(Type.CON);
		}
		if (request.getType() == Type.CON) {
			LOGGER.debug("{} prepare retransmission for {}", exchange, request);
			prepareRetransmission(exchange, new RetransmissionTask(exchange, request) {

				public void retransmit() {
					if (request.getEffectiveDestinationContext() != request.getDestinationContext()) {
						exchange.resetEndpointContext();
					}
					sendRequest(exchange, request);
				}
			});
		}
		lower().sendRequest(exchange, request);
	}

	/**
	 * Makes sure that the response type is correct. The response type for a NON
	 * can be NON or CON. The response type for a CON should either be an ACK
	 * with a piggy-backed response or, if an empty ACK has already be sent, a
	 * CON or NON with a separate response.
	 */
	@Override
	public void sendResponse(final Exchange exchange, final Response response) {

		LOGGER.debug("{} send response {}, failed transmissions: {}", exchange, response,
				exchange.getFailedTransmissionCount());

		// If a response type is set, we do not mess around with it.
		// Only if none is set, we have to decide for one here.

		Type respType = response.getType();
		if (respType == null) {
			Type reqType = exchange.getCurrentRequest().getType();
			if (exchange.getCurrentRequest().acknowledge()) {
				// send piggy-backed response
				response.setType(Type.ACK);
				response.setMID(exchange.getCurrentRequest().getMID());
			} else {
				// send separate CON or NON response depending on the request's type
				response.setType(reqType);
			}

			LOGGER.trace("{} switched response message type from {} to {} (request was {})", exchange, respType,
					response.getType(), reqType);

		} else if (respType == Type.ACK || respType == Type.RST) {
			response.setMID(exchange.getCurrentRequest().getMID());
		}

		if (response.getType() == Type.CON) {
			LOGGER.debug("{} prepare retransmission for {}", exchange, response);
			prepareRetransmission(exchange, new RetransmissionTask(exchange, response) {

				public void retransmit() {
					sendResponse(exchange, response);
				}
			});
		}
		lower().sendResponse(exchange, response);
	}

	/**
	 * Computes the back-off timer and schedules the specified retransmission
	 * task.
	 * 
	 * @param exchange the exchange
	 * @param task the retransmission task
	 */
	private void prepareRetransmission(final Exchange exchange, final RetransmissionTask task) {

		// prevent RejectedExecutionException
		if (executor.isShutdown()) {
			LOGGER.info("Endpoint is being destroyed: skipping retransmission");
			return;
		}

		exchange.setRetransmissionHandle(null); // cancel before reschedule
		updateRetransmissionTimeout(exchange, task.getReliabilityLayerParameters());

		task.message.addMessageObserver(new MessageObserverAdapter(true) {

			@Override
			public void onSent(boolean retransmission) {
				task.message.removeMessageObserver(this);
				if (!exchange.isComplete()) {
					exchange.execute(new Runnable() {

						@Override
						public void run() {
							task.startTimer();
						}
					});
				}
			}

		});
	}

	/**
	 * When we receive a duplicate of a request, we stop it here and do not
	 * forward it to the upper layer. If the server has already sent a response,
	 * we send it again. If the request has only been acknowledged (but the ACK
	 * has gone lost or not reached the client yet), we resent the ACK. If the
	 * request has neither been responded, acknowledged or rejected yet, the
	 * server has not yet decided what to do with the request and we cannot do
	 * anything.
	 */
	@Override
	public void receiveRequest(final Exchange exchange, final Request request) {

		if (request.isDuplicate()) {
			if (exchange.getSendNanoTimestamp() > request.getNanoTimestamp()) {
				// received before response was sent
				int count = counter.incrementAndGet();
				LOGGER.debug("{}: {} duplicate request {}, server sent response delayed, ignore request", count,
						exchange, request);
				return;
			}

			// Request is a duplicate, so resend ACK, RST or response
			exchange.retransmitResponse();
			Response currentResponse = exchange.getCurrentResponse();
			if (currentResponse != null) {
				Type type = currentResponse.getType();
				if (type == Type.NON || type == Type.CON) {
					// separate response
					if (request.isConfirmable()) {
						// resend ACK,
						// comply to RFC 7252, 4.2, cross-layer behavior
						if (request.acknowledge()) {
							EmptyMessage ack = EmptyMessage.newACK(request);
							sendEmptyMessage(exchange, ack);
						}
					}
					if (type == Type.CON) {
						// retransmission cycle
						if (currentResponse.isAcknowledged()) {
							LOGGER.debug("{} request duplicate: ignore, response already acknowledged!", exchange);
						} else {
							int failedCount = exchange.getFailedTransmissionCount() + 1;
							exchange.setFailedTransmissionCount(failedCount);
							LOGGER.debug("{} request duplicate: retransmit response, failed: {}, response: {}",
									exchange, failedCount, currentResponse);
							currentResponse.retransmitting();
							sendResponse(exchange, currentResponse);
						}
						return;
					} else if (currentResponse.isNotification()) {
						// notifications are kept in the exchange store, so
						// prepare retransmission counter for retransmission
						int failedCount = exchange.getFailedTransmissionCount() + 1;
						exchange.setFailedTransmissionCount(failedCount);
					}
				}
				LOGGER.debug("{} respond with the current response to the duplicate request", exchange);
				// Do not restart retransmission cycle
				lower().sendResponse(exchange, currentResponse);

			} else if (exchange.getCurrentRequest().isAcknowledged()) {
				LOGGER.debug("{} duplicate request was acknowledged but no response computed yet. Retransmit ACK",
						exchange);
				EmptyMessage ack = EmptyMessage.newACK(request);
				sendEmptyMessage(exchange, ack);

			} else if (exchange.getCurrentRequest().isRejected()) {
				LOGGER.debug("{} duplicate request was rejected. Reject again", exchange);
				EmptyMessage rst = EmptyMessage.newRST(request);
				sendEmptyMessage(exchange, rst);

			} else {
				LOGGER.debug("{} server has not yet decided what to do with the request. We ignore the duplicate.",
						exchange);
				// The server has not yet decided, whether to acknowledge or
				// reject the request. We know for sure that the server has
				// received the request though and can drop this duplicate here.
			}

		} else {
			// Request is not a duplicate
			exchange.setCurrentRequest(request);
			upper().receiveRequest(exchange, request);
		}
	}

	/**
	 * When we receive a Confirmable response, we acknowledge it and it also
	 * counts as acknowledgment for the request. If the response is a duplicate,
	 * we stop it here and do not forward it to the upper layer.
	 */
	@Override
	public void receiveResponse(final Exchange exchange, final Response response) {

		exchange.setFailedTransmissionCount(0);
		exchange.setRetransmissionHandle(null);

		if (response.getType() == Type.CON) {
			boolean ack = true;
			if (response.isDuplicate()) {
				if (response.getNanoTimestamp() < exchange.getSendNanoTimestamp()) {
					// received response duplicate before ACK/RST
					// or last request retransmission was sent
					// => drop response
					// Note: if the response is received the 1. time, no ACK nor RST was sent
					// so far. Therefore the send timestamp is related to the request
					// retransmission only. In that case always ACK/RST to try stopping future
					// response retransmissions.
					int count = counter.incrementAndGet();
					LOGGER.debug("{}: {} duplicate response {}, server sent ACK delayed, ignore response", count,
							exchange, response);
					return;
				}
				// resend last ack or rst, don't update, request state may have changed!
				if (response.isRejected()) {
					ack = false;
					LOGGER.debug("{} reject duplicate CON response, request canceled.", exchange);
				} else {
					LOGGER.debug("{} acknowledging duplicate CON response", exchange);
				}
			} else {
				if (exchange.getRequest().isCanceled()) {
					ack = false;
					LOGGER.debug("{} reject CON response, request canceled.", exchange);
				} else {
					LOGGER.debug("{} acknowledging CON response", exchange);
				}
			}
			EmptyMessage empty;
			if (ack) {
				empty = EmptyMessage.newACK(response);
				response.setAcknowledged(true);
			} else {
				empty = EmptyMessage.newRST(response);
				response.setRejected(true);
			}
			sendEmptyMessage(exchange, empty);
		}

		if (response.isDuplicate()) {
			if (response.getType() != Type.CON) {
				LOGGER.debug("{} ignoring duplicate response", exchange);
			}
		} else {
			exchange.getCurrentRequest().setAcknowledged(true);
			exchange.setCurrentResponse(response);
			upper().receiveResponse(exchange, response);
		}
	}

	/**
	 * If we receive an ACK or RST, we mark the outgoing request or response as
	 * acknowledged or rejected respectively and cancel its retransmission.
	 */
	@Override
	public void receiveEmptyMessage(final Exchange exchange, final EmptyMessage message) {

		exchange.setFailedTransmissionCount(0);
		exchange.setRetransmissionHandle(null);
		// TODO: If this is an observe relation, the current response might not
		// be the one that is being acknowledged. The current response might
		// already be the next NON notification.
		String type;
		Message currentMessage;
		if (exchange.isOfLocalOrigin()) {
			type = "request";
			currentMessage = exchange.getCurrentRequest();
		} else {
			type = "response";
			currentMessage = exchange.getCurrentResponse();
		}
		int observer = currentMessage.getMessageObservers().size();
		if (message.getType() == Type.ACK) {
			LOGGER.debug("{} acknowledge {} for {} {} ({} msg observer)", exchange, message, type, currentMessage,
					observer);
			currentMessage.acknowledge();
		} else if (message.getType() == Type.RST) {
			LOGGER.debug("{} reject {} for {} {} ({} msg observer)", exchange, message, type, currentMessage, observer);
			currentMessage.setRejected(true);
		} else {
			LOGGER.warn("{} received empty message that is neither ACK nor RST: {}", exchange, message);
			return;
		}

		upper().receiveEmptyMessage(exchange, message);
	}

	/**
	 * Update the exchange's current timeout.
	 * 
	 * Prepares either for the first transmission or stretches timeout for
	 * follow-up retransmissions.
	 * 
	 * @param exchange exchange to update the current timeout
	 * @param reliabilityLayerParameters reliability layer's parameter.
	 * @see Exchange#getCurrentTimeout()
	 * @see Exchange#setCurrentTimeout(int)
	 * @see Exchange#getFailedTransmissionCount()
	 */
	protected void updateRetransmissionTimeout(final Exchange exchange, ReliabilityLayerParameters reliabilityLayerParameters) {
		int timeout;
		if (exchange.getFailedTransmissionCount() == 0) {
			/*
			 * For a new confirmable message, the initial timeout is set to a
			 * random number between ACK_TIMEOUT and (ACK_TIMEOUT *
			 * ACK_RANDOM_FACTOR)
			 */
			timeout = getRandomTimeout(reliabilityLayerParameters.getAckTimeout(), reliabilityLayerParameters.getAckRandomFactor());
		} else {
			timeout = (int) (reliabilityLayerParameters.getAckTimeoutScale() * exchange.getCurrentTimeout());
		}
		exchange.setCurrentTimeout(timeout);
	}

	/**
	 * Returns a random timeout between the specified min and max.
	 * 
	 * @param ackTimeout ack timeout in milliseconds
	 * @param randomFactor random factor. Intended to be above 1.5.
	 * @return a random value between ackTimeout and ackTimeout * randomFactor
	 */
	protected int getRandomTimeout(int ackTimeout, float randomFactor) {
		if (randomFactor <= 1.0) {
			return ackTimeout;
		}
		int delta = (int)(ackTimeout * randomFactor) - ackTimeout;
		synchronized (rand) {
			return ackTimeout + rand.nextInt(delta + 1);
		}
	}

	/*
	 * The main reason to create this class was to enable the methods
	 * sendRequest and sendResponse to use the same code for sending messages
	 * but where the retransmission method calls sendRequest and sendResponse
	 * respectively.
	 */
	protected abstract class RetransmissionTask implements Runnable {

		private final Exchange exchange;
		private final Message message;

		public RetransmissionTask(final Exchange exchange, final Message message) {
			this.exchange = exchange;
			this.message = message;
		}

		/**
		 * Get effective reliability layer parameters.
		 * 
		 * @return effective reliability layer parameters.
		 */
		public ReliabilityLayerParameters getReliabilityLayerParameters() {
			ReliabilityLayerParameters parameters = message.getReliabilityLayerParameters();
			if (parameters == null) {
				parameters = defaultReliabilityLayerParameters;
			}
			return parameters;
		}

		public void startTimer() {
			if (!exchange.isComplete()) {
				int timeout = exchange.getCurrentTimeout();
				ScheduledFuture<?> f = executor.schedule(this, timeout, TimeUnit.MILLISECONDS);
				exchange.setRetransmissionHandle(f);
			}
		}

		@Override
		public void run() {
			exchange.execute(new Runnable() {

				@Override
				public void run() {
					retry();
				}
			});
		}

		private void retry() {
			/*
			 * Do not retransmit a message if it has been acknowledged,
			 * rejected, canceled or already been retransmitted for the maximum
			 * number of times.
			 */
			try {
				exchange.setRetransmissionHandle(null);
				if (exchange.isComplete()) {
					LOGGER.debug("Timeout: for {}, {}", exchange, message);
					return;
				}
				int failedCount = exchange.getFailedTransmissionCount() + 1;
				if (failedCount == 1) {
					EndpointContext context = EndpointContextUtil
							.getFollowUpEndpointContext(message.getDestinationContext(), exchange.getEndpointContext());
					message.setEffectiveDestinationContext(context);
				}
				exchange.setFailedTransmissionCount(failedCount);

				LOGGER.debug("Timeout: for {} retry {} of {}", exchange, failedCount, message);

				if (message.isAcknowledged()) {
					LOGGER.trace("Timeout: for {} message already acknowledged, cancel retransmission of {}", exchange,
							message);
					return;

				} else if (message.isRejected()) {
					LOGGER.trace("Timeout: for {} message already rejected, cancel retransmission of {}", exchange,
							message);
					return;

				} else if (message.isCanceled()) {
					LOGGER.trace("Timeout: for {}, {} is canceled, do not retransmit", exchange, message);
					return;

				} else if (failedCount <= getReliabilityLayerParameters().getMaxRetransmit()) {
					LOGGER.debug("Timeout: for {} retransmit message, failed: {}, message: {}", exchange, failedCount,
							message);

					// Trigger MessageObservers
					message.retransmitting();

					// MessageObserver might have canceled
					if (message.isCanceled()) {
						LOGGER.trace("Timeout: for {}, {} got canceled, do not retransmit", exchange, message);
						return;
					}
					retransmit();
				} else {
					LOGGER.debug("Timeout: for {} retransmission limit reached, exchange failed, message: {}", exchange,
							message);
					exchange.setTimedOut(message);
				}
			} catch (Exception e) {
				LOGGER.error("Exception for {} in MessageObserver: {}", exchange, e.getMessage(), e);
			}
		}

		public abstract void retransmit();
	}

}
