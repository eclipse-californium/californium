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

import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.Exchange;


/**
 * A partial implementation of a layer. Override receive and send-methods call
 * their corresponding super.sendX() or super.receiveX()-methods to forward the
 * specified exchange and request, response or empty message to the next layer.
 */
public abstract class AbstractLayer implements Layer {
	
	/** The logger. */
	protected final static Logger LOGGER = Logger.getLogger(AbstractLayer.class.getCanonicalName());
	
	/** The upper layer. */
	private Layer upperLayer;
	
	/** The lower layer. */
	private Layer lowerLayer;
	
	/** The executor. */
	protected ScheduledExecutorService executor;
	
	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.layer.Layer#sendRequest(ch.inf.vs.californium.network.Exchange, ch.inf.vs.californium.coap.Request)
	 */
	@Override
	public void sendRequest(Exchange exchange, Request request) {
		if (lowerLayer != null)
			lowerLayer.sendRequest(exchange, request);
		else LOGGER.severe("No lower layer found to send request "+request);
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.layer.Layer#sendResponse(ch.inf.vs.californium.network.Exchange, ch.inf.vs.californium.coap.Response)
	 */
	@Override
	public void sendResponse(Exchange exchange, Response response) {
		if (lowerLayer != null)
			lowerLayer.sendResponse(exchange, response);
		else LOGGER.severe("No lower layer found to send response "+response);
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.layer.Layer#sendEmptyMessage(ch.inf.vs.californium.network.Exchange, ch.inf.vs.californium.coap.EmptyMessage)
	 */
	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		if (lowerLayer != null)
			lowerLayer.sendEmptyMessage(exchange, message);
		else LOGGER.severe("No lower layer found to send empty message "+message+" for exchange "+exchange);
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.layer.Layer#receiveRequest(ch.inf.vs.californium.network.Exchange, ch.inf.vs.californium.coap.Request)
	 */
	@Override
	public void receiveRequest(Exchange exchange, Request request) {
		if (upperLayer != null)
			upperLayer.receiveRequest(exchange, request);
		else LOGGER.severe("No upper layer found to receive request "+request+" for exchange "+exchange);
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.layer.Layer#receiveResponse(ch.inf.vs.californium.network.Exchange, ch.inf.vs.californium.coap.Response)
	 */
	@Override
	public void receiveResponse(Exchange exchange, Response response) {
		if (upperLayer != null)
			upperLayer.receiveResponse(exchange, response);
		else LOGGER.severe("No upper layer found to receive response "+response+" for exchange "+exchange);
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.layer.Layer#receiveEmptyMessage(ch.inf.vs.californium.network.Exchange, ch.inf.vs.californium.coap.EmptyMessage)
	 */
	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		if (upperLayer != null)
			upperLayer.receiveEmptyMessage(exchange, message);
		else LOGGER.severe("No upper layer found to receive empty message "+message+" for exchange "+exchange);
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.layer.Layer#setLowerLayer(ch.inf.vs.californium.network.layer.Layer)
	 */
	@Override
	public void setLowerLayer(Layer layer) {
		if (lowerLayer != layer) {
			if (lowerLayer != null)
				lowerLayer.setUpperLayer(null);
			lowerLayer = layer;
			lowerLayer.setUpperLayer(this);
		}
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.layer.Layer#setUpperLayer(ch.inf.vs.californium.network.layer.Layer)
	 */
	@Override
	public void setUpperLayer(Layer layer) {
		if (upperLayer != layer) {
			if (upperLayer != null)
				upperLayer.setLowerLayer(null);
			upperLayer = layer;
			upperLayer.setLowerLayer(this);
		}
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.layer.Layer#setExecutor(java.util.concurrent.ScheduledExecutorService)
	 */
	@Override
	public void setExecutor(ScheduledExecutorService executor) {
		this.executor = executor;
	}
	
	/**
	 * Reject the specified message. Rejecting an ACK or RST is not allowed.
	 *
	 * @param exchange the exchange, can be null
	 * @param message the message
	 * @throws IllegalArgumentException if the message's type is ACK or RST
	 */
	public void reject(Exchange exchange, Message message) {
		/*
		 * From core-coap draft 14:
		 * More generally, Acknowledgement and Reset messages MUST NOT elicit
		 * any Acknowledgement or Reset message from their recipient. (draft-14)
		 */
		if (message.getType() == Type.ACK || message.getType() == Type.RST)
			throw new IllegalArgumentException("Rejecting an "+message.getType()+" is not allowed");
		sendEmptyMessage(exchange, EmptyMessage.newRST(message));
	}
	
}
