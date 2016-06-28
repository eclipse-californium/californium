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

import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Outbox;
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
 * | | {@link ExchangeCleanupLayer} | |
 * * | +-------------------+ |
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
public class CoapUdpStack implements CoapStack {

	/** The LOGGER. */
	private final static Logger LOGGER = Logger.getLogger(CoapStack.class.getCanonicalName());

	private List<Layer> layers;
	private Outbox outbox;
	private StackTopAdapter top;
	private StackBottomAdapter bottom;
	private MessageDeliverer deliverer;

	public CoapUdpStack(NetworkConfig config, Outbox outbox) {
		this.top = new StackTopAdapter();
		this.outbox = outbox;

		ReliabilityLayer reliabilityLayer;
		if (config.getBoolean(NetworkConfig.Keys.USE_CONGESTION_CONTROL) == true) {
			reliabilityLayer = CongestionControlLayer.newImplementation(config);
			LOGGER.log(Level.CONFIG, "Enabling congestion control: {0}", reliabilityLayer.getClass().getSimpleName());
		} else {
			reliabilityLayer = new ReliabilityLayer(config);
		}

		this.layers = new Layer.TopDownBuilder()
				.add(top)
				.add(new ExchangeCleanupLayer())
				.add(new ObserveLayer(config))
				.add(new BlockwiseLayer(config))
				.add(reliabilityLayer)
				.add(bottom = new StackBottomAdapter())
				.create();

		// make sure the endpoint sets a MessageDeliverer
	}

	@Override
	public void sendRequest(Request request) {
		// delegate to top
		top.sendRequest(request);
	}

	@Override
	public void sendResponse(Exchange exchange, Response response) {
		// delegate to top
		top.sendResponse(exchange, response);
	}

	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		// delegate to top
		top.sendEmptyMessage(exchange, message);
	}

	@Override
	public void receiveRequest(Exchange exchange, Request request) {
		// delegate to bottom
		bottom.receiveRequest(exchange, request);
	}

	@Override
	public void receiveResponse(Exchange exchange, Response response) {
		// delegate to bottom
		bottom.receiveResponse(exchange, response);
	}

	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		// delegate to bottom
		bottom.receiveEmptyMessage(exchange, message);
	}

	@Override
	public void setExecutor(ScheduledExecutorService executor) {
		for (Layer layer:layers)
			layer.setExecutor(executor);
	}

	@Override
	public void setDeliverer(MessageDeliverer deliverer) {
		this.deliverer = deliverer;
	}

	@Override
	public void destroy() {
		for (Layer layer:layers)
			layer.destroy();
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
			// we always complete the message exchange when we have received a response
			exchange.setComplete();
			if (hasDeliverer()) {
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
			outbox.sendRequest(exchange, request);
		}

		@Override
		public void sendResponse(Exchange exchange, Response response) {
			outbox.sendResponse(exchange, response);
		}

		@Override
		public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
			outbox.sendEmptyMessage(exchange, message);
		}

	}

	@Override
	public boolean hasDeliverer() {
		return deliverer != null;
	}
}
