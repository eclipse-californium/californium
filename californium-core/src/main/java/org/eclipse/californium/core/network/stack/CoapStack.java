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

import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.Connector;


/**
 * The CoAPStack builds up the stack of CoAP layers that process the CoAP
 * protocol.
 * <p>
 * The complete process for incoming and outgoing messages is visualized below.
 * The class <code>CoapStack</code> builds up the part between the Stack Top and
 * Bottom.
 * <hr><blockquote><pre>
 * +-----------------------+
 * | {@link MessageDeliverer}      |
 * +-------------A---------+
 *               A
 *             * A
 * +-----------+-A---------+
 * |       CoAPEndpoint    |
 * |           v A         |
 * |           v A         |
 * | +---------v-+-------+ |
 * | | Stack Top         | |
 * | +-------------------+ |
 * | | {@link TokenLayer }        | |
 * | +-------------------+ |
 * | | {@link ObserveLayer}      | |
 * | +-------------------+ |
 * | | {@link BlockwiseLayer}    | |
 * | +-------------------+ |
 * | | {@link ReliabilityLayer}  | |
 * | +-------------------+ |
 * | | Stack Bottom      | |
 * | +---------+-A-------+ |
 * |           v A         |
 * |         Matcher       |
 * |           v A         |
 * |       Interceptor     |
 * |           v A         |
 * +-----------v-A---------+
 *             v A 
 *             v A 
 * +-----------v-+---------+
 * | {@link Connector}             |
 * +-----------------------+
 * </pre></blockquote><hr>
 */
public class CoapStack {

	/** The LOGGER. */
	final static Logger LOGGER = Logger.getLogger(CoapStack.class.getCanonicalName());

	/** The list of layers. */
	private List<Layer> layers;
	
	/** The channel. */
	private ExchangeForwarder forwarder;

	/** The top of the stack. */
	private StackTopAdapter top;
	
	/** The bottom of the stack. */
	private StackBottomAdapter bottom;

	private MessageDeliverer deliverer;
	
	public CoapStack(NetworkConfig config, ExchangeForwarder forwarder) {
		this.top = new StackTopAdapter();
		this.forwarder = forwarder;
		this.layers = 
				new Layer.TopDownBuilder()
				.add(top)
				.add(new ObserveLayer(config))
				.add(new BlockwiseLayer(config))
				.add(new TokenLayer(config))
				.add(new ReliabilityLayer(config))
				.add(bottom = new StackBottomAdapter())
				.create();
		this.deliverer = new EndpointManager.ClientMessageDeliverer();
	}
	
	// delegate to top
	public void sendRequest(Request request) {
		top.sendRequest(request);
	}

	// delegate to top
	public void sendResponse(Exchange exchange, Response response) {
		top.sendResponse(exchange, response);
	}

	// delegate to top
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		top.sendEmptyMessage(exchange, message);
	}

	// delegate to bottom
	public void receiveRequest(Exchange exchange, Request request) {
		bottom.receiveRequest(exchange, request);
	}

	// delegate to bottom
	public void receiveResponse(Exchange exchange, Response response) {
		bottom.receiveResponse(exchange, response);
	}

	// delegate to bottom
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		bottom.receiveEmptyMessage(exchange, message);
	}

	public void setExecutor(ScheduledExecutorService executor) {
		for (Layer layer:layers)
			layer.setExecutor(executor);
	}
	
	public void setDeliverer(MessageDeliverer deliverer) {
		this.deliverer = deliverer;
	}
	
	private class StackTopAdapter extends AbstractLayer {
		
		public void sendRequest(Request request) {
			Exchange exchange = new Exchange(request, Origin.LOCAL);
			sendRequest(exchange, request); // layer method
		}
		
		@Override
		public void sendRequest(Exchange exchange, Request request) {
			exchange.setRequest(request);
			super.sendRequest(exchange, request);
		}
		
		@Override
		public void sendResponse(Exchange exchange, Response response) {
			exchange.setResponse(response);
			super.sendResponse(exchange, response);
		}
		
		@Override
		public void receiveRequest(Exchange exchange, Request request) {
			// if there is no BlockwiseLayer we still have to set it
			if (exchange.getRequest() == null)
				exchange.setRequest(request);
			if (deliverer != null) {
				deliverer.deliverRequest(exchange);
			} else {
				LOGGER.severe("Top of CoAP stack has no deliverer to deliver request");
			}
		}

		@Override
		public void receiveResponse(Exchange exchange, Response response) {
			if (!response.getOptions().hasObserve())
				exchange.setComplete();
			if (deliverer != null) {
				deliverer.deliverResponse(exchange, response); // notify request that response has arrived
			} else {
				LOGGER.severe("Top of CoAP stack has no deliverer to deliver response");
			}
		}
		
		@Override
		public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
			// When empty messages reach the top of the CoAP stack we can ignore them. 
		}
	}
	
	private class StackBottomAdapter extends AbstractLayer {
	
		@Override
		public void sendRequest(Exchange exchange, Request request) {
			forwarder.sendRequest(exchange, request);
		}

		@Override
		public void sendResponse(Exchange exchange, Response response) {
			forwarder.sendResponse(exchange, response);
		}

		@Override
		public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
			forwarder.sendEmptyMessage(exchange, message);
		}
		
	}
	
	public boolean hasDeliverer() {
		return deliverer != null;
	}
}
