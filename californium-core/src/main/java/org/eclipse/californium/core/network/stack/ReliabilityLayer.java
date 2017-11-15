/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.Random;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;

/**
 * The reliability layer. CON retransmission. ACK/RST processing.
 */
public class ReliabilityLayer extends AbstractLayer {

	/** The logger. */
	protected final static Logger LOGGER = Logger.getLogger(ReliabilityLayer.class.getCanonicalName());

	/** The random numbers generator for the back-off timer */
	private final Random rand = new Random();

	private final int ack_timeout;
	private final float ack_random_factor;
	private final float ack_timeout_scale;
	private final int max_retransmit;

	/**
	 * Constructs a new reliability layer. Changes to the configuration are
	 * observed and automatically applied.
	 * 
	 * @param config the configuration
	 */
	public ReliabilityLayer(final NetworkConfig config) {
		ack_timeout = config.getInt(NetworkConfig.Keys.ACK_TIMEOUT);
		ack_random_factor = config.getFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR);
		ack_timeout_scale = config.getFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE);
		max_retransmit = config.getInt(NetworkConfig.Keys.MAX_RETRANSMIT);

		LOGGER.log(Level.CONFIG, "ReliabilityLayer uses ACK_TIMEOUT={0}, ACK_RANDOM_FACTOR={1}, and ACK_TIMEOUT_SCALE={2}",
				new Object[]{ack_timeout, ack_random_factor, ack_timeout_scale});
	}

	/**
	 * Schedules a retransmission for confirmable messages.
	 */
	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		LOGGER.log(Level.FINER, "Send request, failed transmissions: {0}", exchange.getFailedTransmissionCount());

		if (request.getType() == null) {
			request.setType(Type.CON);
		}
		if (request.getType() == Type.CON) {
			prepareRetransmission(exchange, new RetransmissionTask(exchange, request) {

				public void retransmit() {
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

		LOGGER.log(Level.FINER, "Send response, failed transmissions: {0}", exchange.getFailedTransmissionCount());

		// If a response type is set, we do not mess around with it.
		// Only if none is set, we have to decide for one here.

		Type respType = response.getType();
		if (respType == null) {
			Type reqType = exchange.getCurrentRequest().getType();
			if (reqType == Type.CON) {
				if (exchange.getCurrentRequest().isAcknowledged()) {
					// send separate response
					response.setType(Type.CON);
				} else {
					exchange.getCurrentRequest().setAcknowledged(true);
					// send piggy-backed response
					response.setType(Type.ACK);
					response.setMID(exchange.getCurrentRequest().getMID());
				}
			} else {
				// send NON response
				response.setType(Type.NON);
			}

			LOGGER.log(Level.FINEST, "Switched response message type from {0} to {1} (request was {2})", new Object[] {
					respType, response.getType(), reqType });

		} else if (respType == Type.ACK || respType == Type.RST) {
			response.setMID(exchange.getCurrentRequest().getMID());
		}

		if (response.getType() == Type.CON) {
			LOGGER.finer("Scheduling retransmission for " + response);
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
	protected void prepareRetransmission(final Exchange exchange, final RetransmissionTask task) {

		// prevent RejectedExecutionException
		if (executor.isShutdown()) {
			LOGGER.info("Endpoint is being destroyed: skipping retransmission");
			return;
		}

		/*
		 * For a new confirmable message, the initial timeout is set to a random
		 * number between ACK_TIMEOUT and (ACK_TIMEOUT * ACK_RANDOM_FACTOR)
		 */
		synchronized(exchange) {
			int timeout;
			if (exchange.getFailedTransmissionCount() == 0) {
				timeout = getRandomTimeout(ack_timeout, (int) (ack_timeout * ack_random_factor));
			} else {
				timeout = (int) (ack_timeout_scale * exchange.getCurrentTimeout());
			}
			exchange.setCurrentTimeout(timeout);
			exchange.setRetransmissionHandle(null); // cancel before reschedule
			ScheduledFuture<?> f = executor.schedule(task, timeout, TimeUnit.MILLISECONDS);
			exchange.setRetransmissionHandle(f);
		}
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
			// Request is a duplicate, so resend ACK, RST or response
			if (exchange.getCurrentResponse() != null) {
				LOGGER.fine("Respond with the current response to the duplicate request");
				// Do not restart retransmission cycle
				lower().sendResponse(exchange, exchange.getCurrentResponse());

			} else if (exchange.getCurrentRequest().isAcknowledged()) {
				LOGGER.fine("The duplicate request was acknowledged but no response computed yet. Retransmit ACK");
				EmptyMessage ack = EmptyMessage.newACK(request);
				sendEmptyMessage(exchange, ack);

			} else if (exchange.getCurrentRequest().isRejected()) {
				LOGGER.fine("The duplicate request was rejected. Reject again");
				EmptyMessage rst = EmptyMessage.newRST(request);
				sendEmptyMessage(exchange, rst);

			} else {
				LOGGER.fine("The server has not yet decided what to do with the request. We ignore the duplicate.");
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
		exchange.getCurrentRequest().setAcknowledged(true);
		exchange.setRetransmissionHandle(null);

		if (response.getType() == Type.CON && !exchange.getRequest().isCanceled()) {
			LOGGER.finer("acknowledging CON response");
			EmptyMessage ack = EmptyMessage.newACK(response);
			sendEmptyMessage(exchange, ack);
		}

		if (response.isDuplicate()) {
			LOGGER.fine("ignoring duplicate response");
		} else {
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
		// TODO: If this is an observe relation, the current response might not
		// be the one that is being acknowledged. The current response might
		// already be the next NON notification.

		if (message.getType() == Type.ACK) {
			if (exchange.isOfLocalOrigin()) {
				exchange.getCurrentRequest().setAcknowledged(true);
			} else {
				exchange.getCurrentResponse().setAcknowledged(true);
			}
		} else if (message.getType() == Type.RST) {
			if (exchange.isOfLocalOrigin()) {
				exchange.getCurrentRequest().setRejected(true);
			} else {
				exchange.getCurrentResponse().setRejected(true);
			}
		} else {
			LOGGER.log(Level.WARNING, "received empty message that is neither ACK nor RST: {0}", message);
		}

		exchange.setRetransmissionHandle(null);

		upper().receiveEmptyMessage(exchange, message);
	}

	/*
	 * Returns a random timeout between the specified min and max.
	 * 
	 * @param min the min
	 * @param max the max
	 * @return a random value between min and max
	 */
	protected int getRandomTimeout(final int min, final int max) {
		if (min == max) {
			return min;
		}
		synchronized (rand) {
			return min + rand.nextInt(max - min);
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

		@Override
		public void run() {
			/*
			 * Do not retransmit a message if it has been acknowledged,
			 * rejected, canceled or already been retransmitted for the maximum
			 * number of times.
			 */
			try {
				int failedCount;
				synchronized(exchange) {
					failedCount = exchange.getFailedTransmissionCount() + 1;
					exchange.setFailedTransmissionCount(failedCount);
				}
				if (message.isAcknowledged()) {
					LOGGER.log(Level.FINEST, "Timeout: message already acknowledged, cancel retransmission of {0}", message);
					return;

				} else if (message.isRejected()) {
					LOGGER.log(Level.FINEST, "Timeout: message already rejected, cancel retransmission of {0}", message);
					return;

				} else if (message.isCanceled()) {
					LOGGER.log(Level.FINEST, "Timeout: canceled (MID={0}), do not retransmit", message.getMID());
					return;

				} else if (failedCount <= max_retransmit) {
					LOGGER.log(Level.FINER, "Timeout: retransmit message, failed: {0}, message: {1}", new Object[]{failedCount, message});

					// Trigger MessageObservers
					message.retransmitting();

					// MessageObserver might have canceled
					if (message.isCanceled()) {
						LOGGER.log(Level.FINER, "Timeout: canceled (MID={0}), do not retransmit", message.getMID());
						return;
					}
					retransmit();
				} else {
					LOGGER.log(Level.FINE, "Timeout: retransmission limit reached, exchange failed, message: {0}", message);
					exchange.setTimedOut();
					message.setTimedOut(true);
				}
			} catch (Exception e) {
				LOGGER.log(Level.SEVERE, String.format("Exception in MessageObserver: %s", e.getMessage()), e);
			}
		}

		public abstract void retransmit();
	}
}
