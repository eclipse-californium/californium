/*******************************************************************************
 * Copyright (c) 2014 Institute for Pervasive Computing, ETH Zurich and others.
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

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.observe.ObserveRelation;


public class ObserveLayer extends AbstractLayer {

	public ObserveLayer(NetworkConfig config) {
		// so far no configuration values for this layer
	}
	
	@Override
	public void sendRequest(Exchange exchange, Request request) {
		super.sendRequest(exchange, request);
	}
	
	@Override
	public void sendResponse(final Exchange exchange, Response response) {
		final ObserveRelation relation = exchange.getRelation();
		if (relation != null && relation.isEstablished()) {
			
			if (exchange.getRequest().isAcknowledged() || exchange.getRequest().getType()==Type.NON) {
				// Transmit errors as CON
				if (!ResponseCode.isSuccess(response.getCode())) {
					LOGGER.fine("Response has error code "+response.getCode()+" and must be sent as CON");
					response.setType(Type.CON);
					relation.cancel();
				} else {
					// Make sure that every now and than a CON is mixed within
					if (relation.check()) {
						LOGGER.fine("The observe relation check requires the notification to be sent as CON");
						response.setType(Type.CON);
					} else {
						// By default use NON, but do not override resource decision
						if (response.getType()==null) response.setType(Type.NON);
					}
				}
			}
			
			// This is a notification
			response.setLast(false);
			
			/*
			 * The matcher must be able to find the NON notifications to remove
			 * them from the exchangesByMID hashmap
			 */
			if (response.getType() == Type.NON) {
				relation.addNotification(response);
			}
			
			/*
			 * Only one Confirmable message is allowed to be in transit. A CON
			 * is in transit as long as it has not been acknowledged, rejected,
			 * or timed out. All further notifications are postponed here. If a
			 * former CON is acknowledged or timeouts, it starts the freshest
			 * notification (In case of a timeout, it keeps the retransmission
			 * counter). When a fresh/younger notification arrives but must be
			 * postponed we forget any former notification.
			 */
			if (response.getType() == Type.CON) {
				prepareSelfReplacement(exchange, response);
			}
			
			// The decision whether to postpone this notification or not and the
			// decision which notification is the freshest to send next must be
			// synchronized
			synchronized (exchange) {
				Response current = relation.getCurrentControlNotification();
				if (current != null && isInTransit(current)) {
					LOGGER.fine("A former notification is still in transit. Postpone " + response);
					// use the same MID
					response.setMID(current.getMID());
					relation.setNextControlNotification(response);
					// do not send now
					return;
				} else {
					relation.setCurrentControlNotification(response);
					relation.setNextControlNotification(null);
				}
			}

		} // else no observe was requested or the resource does not allow it
		super.sendResponse(exchange, response);
	}
	
	/**
	 * Returns true if the specified response is still in transit. A response is
	 * in transit if it has not yet been acknowledged, rejected or its current
	 * transmission has not yet timed out. 
	 */
	private boolean isInTransit(Response response) {
		Type type = response.getType();
		boolean acked = response.isAcknowledged();
		boolean timeout = response.isTimedOut();
		boolean result = type == Type.CON && !acked && !timeout;
		return result;
	}

	@Override
	public void receiveResponse(Exchange exchange, Response response) {
		if (response.getOptions().hasObserve() && exchange.getRequest().isCanceled()) {
			// The request was canceled and we no longer want notifications
			LOGGER.finer("ObserveLayer rejecting notification for canceled Exchange");
			EmptyMessage rst = EmptyMessage.newRST(response);
			sendEmptyMessage(exchange, rst);
			// Matcher sets exchange as complete when RST is sent
		} else {
			// No observe option in response => always deliver
			super.receiveResponse(exchange, response);
		}
	}
	
	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		// NOTE: We could also move this into the MessageObserverAdapter from
		// sendResponse into the method rejected().
		if (message.getType() == Type.RST && exchange.getOrigin() == Origin.REMOTE) {
			// The response has been rejected
			ObserveRelation relation = exchange.getRelation();
			if (relation != null) {
				relation.cancel();
			} // else there was no observe relation ship and this layer ignores the rst
		}
		super.receiveEmptyMessage(exchange, message);
	}
	
	private void prepareSelfReplacement(Exchange exchange, Response response) {
		response.addMessageObserver(new NotificationController(exchange, response));
	}
	
	/**
	 * Sends the next CON as soon as the former CON is no longer in transit.
	 */
	private class NotificationController extends MessageObserverAdapter {
		
		private Exchange exchange;
		private Response response;
		
		public NotificationController(Exchange exchange, Response response) {
			this.exchange = exchange;
			this.response = response;
		}
		
		@Override
		public void onAcknowledgement() {
			synchronized (exchange) {
				ObserveRelation relation = exchange.getRelation();
				final Response next = relation.getNextControlNotification();
				relation.setCurrentControlNotification(next); // next may be null
				relation.setNextControlNotification(null);
				if (next != null) {
					LOGGER.fine("Notification has been acknowledged, send the next one");
					// this is not a self replacement, hence a new MID
					next.setMID(Message.NONE);
					// Create a new task for sending next response so that we can leave the sync-block
					executor.execute(new Runnable() {
						public void run() {
							ObserveLayer.super.sendResponse(exchange, next);
						}
					});
				}
			}
		}
		
		@Override
		public void onRetransmission() {
			synchronized (exchange) {
				ObserveRelation relation = exchange.getRelation();
				final Response next = relation.getNextControlNotification();
				if (next != null) {
					LOGGER.fine("The notification has timed out and there is a fresher notification for the retransmission");
					// Cancel the original retransmission and send the fresh notification here
					response.cancel();
					// use the same MID
					next.setMID(response.getMID());
					// Convert all notification retransmissions to CON
					if (next.getType() != Type.CON) {
						next.setType(Type.CON);
						prepareSelfReplacement(exchange, next);
					}
					relation.setCurrentControlNotification(next);
					relation.setNextControlNotification(null);
					// Create a new task for sending next response so that we can leave the sync-block
					executor.execute(new Runnable() {
						public void run() {
							ObserveLayer.super.sendResponse(exchange, next);
						}
					});
				}
			}
		}

		@Override
		public void onTimeout() {
			ObserveRelation relation = exchange.getRelation();
			LOGGER.info("Notification " + relation.getExchange().getRequest().getTokenString() + " timed out. Cancel all relations with source " + relation.getSource());
			relation.cancelAll();
		}
		
		// Cancellation on RST is done in receiveEmptyMessage()
	}
}
