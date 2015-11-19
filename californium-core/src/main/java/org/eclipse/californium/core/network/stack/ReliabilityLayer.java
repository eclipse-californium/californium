/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.Random;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.config.NetworkConfigObserverAdapter;


/**
 * The reliability layer 
 */
public class ReliabilityLayer extends AbstractLayer {

	/** The logger. */
	protected final static Logger LOGGER = Logger.getLogger(ReliabilityLayer.class.getCanonicalName());
	private final NetworkConfig config;
	private final NetworkConfigObserverAdapter observer;

	/** The random numbers generator for the back-off timer */
	private Random rand = new Random();
	
	private int ack_timeout;
	private float ack_random_factor;
	private float ack_timeout_scale;
	private int max_retransmit;

	/**
	 * Constructs a new reliability layer.
	 * Changes to the configuration are observed and automatically applied.
	 * @param config the configuration
	 */
	public ReliabilityLayer(NetworkConfig config) {
		this.config = config;
		ack_timeout = config.getInt(NetworkConfig.Keys.ACK_TIMEOUT);
		ack_random_factor = config.getFloat(NetworkConfig.Keys.ACK_RANDOM_FACTOR);
		ack_timeout_scale = config.getFloat(NetworkConfig.Keys.ACK_TIMEOUT_SCALE);
		max_retransmit = config.getInt(NetworkConfig.Keys.MAX_RETRANSMIT);
		
		LOGGER.config("ReliabilityLayer uses ACK_TIMEOUT="+ack_timeout+", ACK_RANDOM_FACTOR="+ack_random_factor+", and ACK_TIMEOUT_SCALE="+ack_timeout_scale);

		observer = new NetworkConfigObserverAdapter() {
			@Override
			public void changed(String key, int value) {
				if (NetworkConfig.Keys.ACK_TIMEOUT.equals(key))
					ack_timeout = value;
				if (NetworkConfig.Keys.MAX_RETRANSMIT.equals(key))
					max_retransmit = value;
			}
			@Override
			public void changed(String key, float value) {
				if (NetworkConfig.Keys.ACK_RANDOM_FACTOR.equals(key))
					ack_random_factor = value;
				if (NetworkConfig.Keys.ACK_TIMEOUT_SCALE.equals(key))
					ack_timeout_scale = value;
			}
		};
		config.addConfigObserver(observer);
	}
	
	/**
	 * Schedules a retransmission for confirmable messages. 
	 */
	@Override
	public void sendRequest(final Exchange exchange, final Request request) {

		LOGGER.finer("Send request, failed transmissions: "+exchange.getFailedTransmissionCount());
		
		if (request.getType() == null)
			request.setType(Type.CON);
		
		if (request.getType() == Type.CON) {
			prepareRetransmission(exchange, new RetransmissionTask(exchange, request) {
				public void retransmit() {
					sendRequest(exchange, request);
				}
			});
		}
		super.sendRequest(exchange, request);
	}

	/**
	 * Makes sure that the response type is correct. The response type for a NON
	 * can be NON or CON. The response type for a CON should either be an ACK
	 * with a piggy-backed response or, if an empty ACK has already be sent, a
	 * CON or NON with a separate response.
	 */
	@Override
	public void sendResponse(final Exchange exchange, final Response response) {

		LOGGER.finer("Send response, failed transmissions: "+exchange.getFailedTransmissionCount());

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
			
			LOGGER.finest("Switched response message type from "+respType+" to "+response.getType()+" (request was "+reqType+")");
		
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
		super.sendResponse(exchange, response);
	}
	
	
	/**
	 * Computes the back-off timer and schedules the specified retransmission
	 * task.
	 * 
	 * @param exchange the exchange
	 * @param task the retransmission task
	 */
	protected void prepareRetransmission(Exchange exchange, RetransmissionTask task) {
		
		// prevent RejectedExecutionException
		if (executor.isShutdown()) {
			LOGGER.info("Endpoint is being destroyed: skipping retransmission");
			return;
		}
		
		/*
		 * For a new confirmable message, the initial timeout is set to a
		 * random number between ACK_TIMEOUT and (ACK_TIMEOUT *
		 * ACK_RANDOM_FACTOR)
		 */
		int timeout;
		if (exchange.getFailedTransmissionCount() == 0) {
			timeout = getRandomTimeout(ack_timeout, (int) (ack_timeout*ack_random_factor));
		} else {
			timeout = (int) (ack_timeout_scale * exchange.getCurrentTimeout());
		}
		exchange.setCurrentTimeout(timeout);
		ScheduledFuture<?> f = executor.schedule(task , timeout, TimeUnit.MILLISECONDS);
		exchange.setRetransmissionHandle(f);
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
	public void receiveRequest(Exchange exchange, Request request) {
		
		if (request.isDuplicate()) {
			// Request is a duplicate, so resend ACK, RST or response
			if (exchange.getCurrentResponse() != null) {
				LOGGER.fine("Respond with the current response to the duplicate request");
				// Do not restart retransmission cycle
				super.sendResponse(exchange, exchange.getCurrentResponse());
				
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
			super.receiveRequest(exchange, request);
		}
	}

	/**
	 * When we receive a Confirmable response, we acknowledge it and it also
	 * counts as acknowledgment for the request. If the response is a duplicate,
	 * we stop it here and do not forward it to the upper layer.
	 */
	@Override
	public void receiveResponse(Exchange exchange, Response response) {
		exchange.setFailedTransmissionCount(0);
		
		exchange.getCurrentRequest().setAcknowledged(true);
		LOGGER.finest("Cancel any retransmission");
		exchange.setRetransmissionHandle(null);
		
		if (response.getType() == Type.CON && !exchange.getRequest().isCanceled()) {
			LOGGER.finer("Response is confirmable, send ACK");
			EmptyMessage ack = EmptyMessage.newACK(response);
			sendEmptyMessage(exchange, ack);
		}
		
		if (response.isDuplicate()) {
			LOGGER.fine("Response is duplicate, ignore it");
		} else {
			super.receiveResponse(exchange, response);
		}
	}

	/**
	 * If we receive an ACK or RST, we mark the outgoing request or response
	 * as acknowledged or rejected respectively and cancel its retransmission.
	 */
	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		exchange.setFailedTransmissionCount(0);
		// TODO: If this is an observe relation, the current response might not
		// be the one that is being acknowledged. The current response might
		// already be the next NON notification.
		
		if (message.getType() == Type.ACK) {
			if (exchange.getOrigin() == Origin.LOCAL) {
				exchange.getCurrentRequest().setAcknowledged(true);
			} else {
				exchange.getCurrentResponse().setAcknowledged(true);
			}
		} else if (message.getType() == Type.RST) {
			if (exchange.getOrigin() == Origin.LOCAL) {
				exchange.getCurrentRequest().setRejected(true);
			} else {
				exchange.getCurrentResponse().setRejected(true);
			}
		} else {
			LOGGER.warning("Empty messgae was not ACK nor RST: "+message);
		}

		LOGGER.finer("Cancel retransmission");
		exchange.setRetransmissionHandle(null);
		
		super.receiveEmptyMessage(exchange, message);
	}
	
	/*
	 * Returns a random timeout between the specified min and max.
	 * @param min the min
	 * @param max the max
	 * @return a random value between min and max
	 */
	protected int getRandomTimeout(int min, int max) {
		if (min == max) return min;
		return min + rand.nextInt(max - min);
	}

	@Override
	public void destroy() {
		config.removeConfigObserver(observer);
	}

	/*
	 * The main reason to create this class was to enable the methods
	 * sendRequest and sendResponse to use the same code for sending messages
	 * but where the retransmission method calls sendRequest and sendResponse
	 * respectively.
	 */
	 protected abstract class RetransmissionTask implements Runnable {
		
		private Exchange exchange;
		private Message message;
		
		public RetransmissionTask(Exchange exchange, Message message) {
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
				int failedCount = exchange.getFailedTransmissionCount() + 1;
				exchange.setFailedTransmissionCount(failedCount);
				
				if (message.isAcknowledged()) {
					LOGGER.finest("Timeout: message already acknowledged, cancel retransmission of "+message);
					return;
					
				} else if (message.isRejected()) {
					LOGGER.finest("Timeout: message already rejected, cancel retransmission of "+message);
					return;
					
				} else if (message.isCanceled()) {
					LOGGER.finest("Timeout: canceled (MID="+message.getMID()+"), do not retransmit");
					return;
					
				} else if (failedCount <= max_retransmit) {
					LOGGER.finer("Timeout: retransmit message, failed: "+failedCount+", message: "+message);
					
					// Trigger MessageObservers
					message.retransmitting();
					
					// MessageObserver might have canceled
					if (!message.isCanceled())
						retransmit();

				} else {
					LOGGER.fine("Timeout: retransmission limit reached, exchange failed, message: "+message);
					exchange.setTimedOut();
					message.setTimedOut(true);
				}
			} catch (Exception e) {
				LOGGER.log(Level.SEVERE, "Exception in MessageObserver: "+e.getMessage(), e);
			}
		}
		
		public abstract void retransmit();
	}
	
}
