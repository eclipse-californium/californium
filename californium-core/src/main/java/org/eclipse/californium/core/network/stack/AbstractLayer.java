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
 * methods of the <em>upperLayer</em> while the <em>send*()</em> methods
 * delegate to the corresponding methods of the <em>lowerLayer</em>.
 * <p>
 * By default the lower and upper layer is set to an instance of {@code LogOnlyLayer}
 * which simply logs the message invocation.
 * <p>
 * Subclasses can selectively override methods in order to implement the
 * desired behavior.
 */
public abstract class AbstractLayer implements Layer {

	/** The logger. */
	private final static Logger LOGGER = Logger.getLogger(AbstractLayer.class.getCanonicalName());

	/** The upper layer. */
	private Layer upperLayer = LogOnlyLayer.getInstance();

	/** The lower layer. */
	private Layer lowerLayer = LogOnlyLayer.getInstance();

	/** The executor. */
	protected ScheduledExecutorService executor;

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {
		lowerLayer.sendRequest(exchange, request);
	}

	@Override
	public void sendResponse(final Exchange exchange, final Response response) {
		lowerLayer.sendResponse(exchange, response);
	}

	@Override
	public void sendEmptyMessage(final Exchange exchange, final EmptyMessage message) {
		lowerLayer.sendEmptyMessage(exchange, message);
	}

	@Override
	public void receiveRequest(final Exchange exchange, final Request request) {
		upperLayer.receiveRequest(exchange, request);
	}

	@Override
	public void receiveResponse(final Exchange exchange, final Response response) {
		upperLayer.receiveResponse(exchange, response);
	}

	@Override
	public void receiveEmptyMessage(final Exchange exchange, final EmptyMessage message) {
		upperLayer.receiveEmptyMessage(exchange, message);
	}

	@Override
	public final void setLowerLayer(final Layer layer) {
		if (lowerLayer != layer) {
			if (lowerLayer != null) {
				lowerLayer.setUpperLayer(null);
			}
			lowerLayer = layer;
			lowerLayer.setUpperLayer(this);
		}
	}

	/**
	 * Gets the lower layer configured for this layer.
	 * 
	 * @return The lower layer.
	 */
	final Layer lower() {
		return lowerLayer;
	}

	@Override
	public final void setUpperLayer(final Layer layer) {
		if (upperLayer != layer) {
			if (upperLayer != null) {
				upperLayer.setLowerLayer(null);
			}
			upperLayer = layer;
			upperLayer.setLowerLayer(this);
		}
	}

	/**
	 * Gets the upper layer configured for this layer.
	 * 
	 * @return The upper layer.
	 */
	final Layer upper() {
		return upperLayer;
	}

	@Override
	public final void setExecutor(final ScheduledExecutorService executor) {
		this.executor = executor;
	}

	/**
	 * Rejects a given message.
	 * <p>
	 * The message is rejected by sending an empty message of type RST echoing
	 * the message's MID.
	 * 
	 * @param exchange The exchange the message is part of or {@code null} if
	 *        the message has been received out of the scope of an exchange.
	 * @param message The message to reject.
	 * @throws IllegalArgumentException if the message is of type ACK or RST.
	 */
	public final void reject(final Exchange exchange, final Message message) {
		if (message.getType() == Type.ACK || message.getType() == Type.RST) {
			throw new IllegalArgumentException("Can only reject CON/NON messages");
		} else {
			lower().sendEmptyMessage(exchange, EmptyMessage.newRST(message));
		}
	}

	/**
	 * This method is empty.
	 * <p>
	 * Subclasses may want to use this method to e.g. shut down the executor.
	 */
	@Override
	public void destroy() {
	}

	/**
	 * A simple layer that just logs every invocation of its methods.
	 *
	 */
	public static final class LogOnlyLayer implements Layer {

		private static final LogOnlyLayer INSTANCE = new LogOnlyLayer();

		/**
		 * Gets the singleton instance.
		 * 
		 * @return The log layer.
		 */
		public static LogOnlyLayer getInstance() {
			return INSTANCE;
		}

		@Override
		public void sendRequest(final Exchange exchange, final Request request) {
			LOGGER.log(Level.SEVERE, "No lower layer set for sending request [{0}]", request);
		}

		@Override
		public void sendResponse(final Exchange exchange, final Response response) {
			LOGGER.log(Level.SEVERE, "No lower layer set for sending response [{0}]", response);
		}

		@Override
		public void sendEmptyMessage(Exchange exchange, EmptyMessage emptyMessage) {
			LOGGER.log(Level.SEVERE, "No lower layer set for sending empty message [{0}]", emptyMessage);
		}

		@Override
		public void receiveRequest(final Exchange exchange, final Request request) {
			LOGGER.log(Level.SEVERE, "No upper layer set for receiving request [{0}]", request);
			
		}

		@Override
		public void receiveResponse(final Exchange exchange, final Response response) {
			LOGGER.log(Level.SEVERE, "No lower layer set for receiving response [{0}]", response);
		}

		@Override
		public void receiveEmptyMessage(final Exchange exchange, final EmptyMessage emptyMessage) {
			LOGGER.log(Level.SEVERE, "No lower layer set for receiving empty message [{0}]", emptyMessage);
		}

		@Override
		public void setLowerLayer(final Layer layer) {
			// do nothing
		}

		@Override
		public void setUpperLayer(final Layer layer) {
			// do nothing
		}

		@Override
		public void setExecutor(final ScheduledExecutorService executor) {
			// do nothing
		}

		@Override
		public void destroy() {
			// do nothing
		}
	}
}
