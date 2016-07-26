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
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.network.Exchange;


/**
 * A base class for implementing a layer.
 * <p>
 * The <em>receive*()</em> methods by default delegate to the corresponding
 * methods of the {@link #upperLayer} (if set) while the <em>send*()</em> methods
 * delegate to the corresponding methods of the {@link #lowerLayer} (if set).
 * </p>
 * <p>
 * Subclasses can selectively override methods in order to implement the
 * desired behavior.
 * </p>
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

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {
		if (lowerLayer != null) {
			lowerLayer.sendRequest(exchange, request);
		} else {
			LOGGER.log(Level.SEVERE, "No lower layer set for sending request [{0}]", request);
		}
	}

	@Override
	public void sendResponse(final Exchange exchange, final Response response) {
		if (lowerLayer != null) {
			lowerLayer.sendResponse(exchange, response);
		} else {
			LOGGER.log(Level.SEVERE, "No lower layer set for sending response [{0}]", response);
		}
	}

	@Override
	public void sendEmptyMessage(final Exchange exchange, final EmptyMessage message) {
		if (lowerLayer != null) {
			lowerLayer.sendEmptyMessage(exchange, message);
		} else {
			LOGGER.log(Level.SEVERE, "No lower layer set for sending empty message [{0}] for exchange [{1}]",
					new Object[]{message, exchange});
		}
	}

	@Override
	public void receiveRequest(final Exchange exchange, final Request request) {
		if (upperLayer != null) {
			upperLayer.receiveRequest(exchange, request);
		} else {
			LOGGER.log(Level.SEVERE, "No upper layer set for receiving request [{0}] for exchange [{1}]",
					new Object[]{request, exchange});
		}
	}

	@Override
	public void receiveResponse(final Exchange exchange, final Response response) {
		if (upperLayer != null) {
			upperLayer.receiveResponse(exchange, response);
		} else {
			LOGGER.log(Level.SEVERE, "No upper layer set for receiving response [{0}] for exchange [{1}]",
					new Object[]{response, exchange});
		}
	}

	@Override
	public void receiveEmptyMessage(final Exchange exchange, final EmptyMessage message) {
		if (upperLayer != null) {
			upperLayer.receiveEmptyMessage(exchange, message);
		} else {
			LOGGER.log(Level.SEVERE, "No upper layer set for receiving empty message [{0}] for exchange [{1}]",
					new Object[]{message, exchange});
		}
	}

	@Override
	public void setLowerLayer(final Layer layer) {
		if (lowerLayer != layer) {
			if (lowerLayer != null) {
				lowerLayer.setUpperLayer(null);
			}
			lowerLayer = layer;
			lowerLayer.setUpperLayer(this);
		}
	}

	@Override
	public void setUpperLayer(final Layer layer) {
		if (upperLayer != layer) {
			if (upperLayer != null) {
				upperLayer.setLowerLayer(null);
			}
			upperLayer = layer;
			upperLayer.setLowerLayer(this);
		}
	}

	@Override
	public void setExecutor(final ScheduledExecutorService executor) {
		this.executor = executor;
	}

	/**
	 * Rejects a given message.
	 * <p>
	 * Rejecting an ACK or RST is not allowed.
	 * </p>
	 * 
	 * @param exchange the exchange the message is part of or {@code null} if
	 *        the message has been received without the scope of an exchange.
	 * @param message the message to reject
	 * @throws IllegalArgumentException if the message is of type ACK or RST.
	 */
	public void reject(final Exchange exchange, final Message message) {
		// From core-coap draft 14:
		// More generally, Acknowledgement and Reset messages MUST NOT elicit
		// any Acknowledgement or Reset message from their recipient. (draft-14)
		if (message.getType() == Type.ACK || message.getType() == Type.RST) {
			throw new IllegalArgumentException("Cannot reject a " + message.getType());
		} else {
			sendEmptyMessage(exchange, EmptyMessage.newRST(message));
		}
	}

	/**
	 * This method is empty.
	 */
	@Override
	public void destroy() {
	}
}
