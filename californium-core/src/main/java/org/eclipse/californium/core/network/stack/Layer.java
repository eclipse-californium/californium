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

import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoAPEndpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;


/**
 * A layer processes requests, responses and empty messages. Layers can be
 * stacked upon each other to compose a processing stack.
 * <p>
 * When the {@link CoAPEndpoint} receives a message, it forwards it to the bottom
 * layer by calling the corresponding receive-method. Each layer processes the
 * message and either forwards it to its upper layer or decides not to. The
 * uppermost layer forwards the message to the {@link MessageDeliverer} which
 * delivers the message to the server, e.g., a request to the target resource or
 * a response to the origin request.
 * <p>
 * When an {@link CoAPEndpoint} sends a message, it forwards it to the uppermost
 * layer by calling the corresponding send-method. Each layer forwards the
 * message to its lower layer. The lowest layer forwards the message back to the
 * endpoint.
 * <p>
 * The {@link Exchange} contains all information concerning an exchange of a
 * request with a response. Layers access the exchange concurrently but in most
 * cases it is only possible for a single thread to be active on fields of the
 * exchange since we usually only deal with one request or one response at time
 * and duplicates are stopped to travel through the stack beforehand. If this is
 * not the case, however, synchronization is required.
 * <p>
 * Each layer should receive a {@link ScheduledExecutorService}. On this
 * executer, any task can be scheduled, e.g., retransmission. Many layers of
 * potentially many endpoints of potentially multiple servers can share the same
 * executor or have separate ones with different properties, e.g., size of
 * thread pool or priority of threads.
 */
public interface Layer {

	/**
	 * Process request before sending.
	 *
	 * @param exchange the exchange
	 * @param request the request
	 */
	public void sendRequest(Exchange exchange, Request request);
	
	/**
	 * Send response.
	 *
	 * @param exchange the exchange
	 * @param response the response
	 */
	public void sendResponse(Exchange exchange, Response response);
	
	/**
	 * Send empty message.
	 *
	 * @param exchange the exchange
	 * @param emptyMessage the empty message
	 */
	public void sendEmptyMessage(Exchange exchange, EmptyMessage emptyMessage);
	
	
	/**
	 * Receive request.
	 *
	 * @param exchange the exchange
	 * @param request the request
	 */
	public void receiveRequest(Exchange exchange, Request request);
	
	/**
	 * Receive response.
	 *
	 * @param exchange the exchange
	 * @param response the response
	 */
	public void receiveResponse(Exchange exchange, Response response);
	
	/**
	 * Receive empty message.
	 *
	 * @param exchange the exchange
	 * @param message the message
	 */
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message);
	
	
	/**
	 * Sets the lower layer.
	 *
	 * @param layer the new lower layer
	 */
	public void setLowerLayer(Layer layer);
	
	/**
	 * Sets the upper layer.
	 *
	 * @param layer the new upper layer
	 */
	public void setUpperLayer(Layer layer);
	
	/**
	 * Sets the executor.
	 *
	 * @param executor the new executor
	 */
	public void setExecutor(ScheduledExecutorService executor);
	
	
	/**
	 * A builder that constructs the stack from the top to the bottom. The
	 * returned list of layers is in the same order as added to the stack.
	 */
	public static class TopDownBuilder {
		
		/** The stack in order as added */
		private LinkedList<Layer> stack = new LinkedList<Layer>();
		
		/**
		 * Adds the specified layer below the currently lowest layer.
		 *
		 * @param layer the layer
		 * @return the builder
		 */
		public TopDownBuilder add(Layer layer) {
			if (stack.size() > 0)
				stack.getLast().setLowerLayer(layer);
			stack.add(layer);
			return this;
		}
		
		/**
		 * Creates the stack.
		 *
		 * @return the stack
		 */
		public List<Layer> create() {
			return stack;
		}
		
	}
	
	/**
	 * A builder that constructs the stack from the bottom upwards. The returned
	 * list of layers is in the same order as added to the stack.
	 */
	public static class BottomUpBuilder {
		
		/** The layers in order as added. */
		private LinkedList<Layer> stack = new LinkedList<Layer>();
		
		/**
		 * Adds the specified layer above the currently uppermost layer.
		 *
		 * @param layer the layer
		 * @return the bottom up builder
		 */
		public BottomUpBuilder add(Layer layer) {
			stack.getLast().setUpperLayer(layer);
			return this;
		}
		
		/**
		 * Creates the stack
		 *
		 * @return the stack
		 */
		public List<Layer> create() {
			return stack;
		}
	}
	
}
