/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Matthias Kovatsch - creator and main architect
 * Martin Lanter - architect and re-implementation
 * Dominique Im Obersteg - parsers and initial implementation
 * Daniel Pauli - parsers and initial implementation
 * Kai Hudalla - logging
 * Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                 explicit String concatenation
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * Achim Kraus (Bosch Software Innovations GmbH) - derived from UDP and TCP CoAP stack
 * Bosch Software Innovations GmbH - migrate to SLF4J
 * Achim Kraus (Bosch Software Innovations GmbH) - support multicast,
 *                                                 move multicast exchange complete
 *                                                 to MulticastCleanupMessageObserver
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.californium.core.coap.BlockOption;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.ExchangeCompleteException;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.stack.Layer.TopDownBuilder;
import org.eclipse.californium.core.server.MessageDeliverer;

/**
 * The BaseCoapStack passes the messages through the layers configured in the
 * stacks implementations.
 */
public abstract class BaseCoapStack implements CoapStack {

	private static final Logger LOGGER = LoggerFactory.getLogger(BaseCoapStack.class.getCanonicalName());

	private List<Layer> layers;
	private final Outbox outbox;
	private final StackTopAdapter top;
	private final StackBottomAdapter bottom;
	private MessageDeliverer deliverer;

	protected BaseCoapStack(final Outbox outbox) {
		this.top = new StackTopAdapter();
		this.bottom = new StackBottomAdapter();
		this.outbox = outbox;
	}

	/**
	 * Sets the layers forming the stack.
	 * <p>
	 * CoAP messages sent to peers will be processed by the layers in the given order
	 * while messages received from peers will be processed in reverse order.
	 * 
	 * @param specificLayers The layers constituting the stack in top-to-bottom order.
	 */
	protected final void setLayers(final Layer specificLayers[]) {
		TopDownBuilder builder = new Layer.TopDownBuilder().add(top);
		for (Layer layer : specificLayers) {
			builder.add(layer);
		}
		builder.add(bottom);
		layers = builder.create();
	}

	@Override
	public void sendRequest(final Exchange exchange, final Request request) {
		// delegate to top
		try {
			top.sendRequest(exchange, request);
		} catch (RuntimeException ex) {
			LOGGER.warn("error send request {}", request, ex);
			request.setSendError(ex);
		}
	}

	@Override
	public void sendResponse(final Exchange exchange, final Response response) {
		// delegate to top
		boolean retransmit = exchange.getRequest().getOptions().hasObserve();
		try {
			if (retransmit) {
				// observe- or cancel-observe-requests may have
				// multiple responses.
				// when observes are finished, the last response has
				// no longer an observe option. Therefore check the
				// request for it.
				exchange.retransmitResponse();
			}
			top.sendResponse(exchange, response);
		} catch (ExchangeCompleteException ex) {
			LOGGER.warn("error send response {}", response, ex);
			response.setSendError(ex);
		} catch (RuntimeException ex) {
			LOGGER.warn("error send response {}", response, ex);
			if (!retransmit) {
				exchange.sendReject();
			}
			response.setSendError(ex);
		}
	}

	@Override
	public void sendEmptyMessage(final Exchange exchange, final EmptyMessage message) {
		// delegate to top
		try {
			top.sendEmptyMessage(exchange, message);
		} catch (RuntimeException ex) {
			LOGGER.warn("error send empty message {}", message, ex);
			message.setSendError(ex);
		}
	}

	@Override
	public void receiveRequest(final Exchange exchange, final Request request) {
		// delegate to bottom
		bottom.receiveRequest(exchange, request);
	}

	@Override
	public void receiveResponse(final Exchange exchange, final Response response) {
		// delegate to bottom
		bottom.receiveResponse(exchange, response);
	}

	@Override
	public void receiveEmptyMessage(final Exchange exchange, final EmptyMessage message) {
		// delegate to bottom
		bottom.receiveEmptyMessage(exchange, message);
	}

	@Override
	public final void setExecutor(final ScheduledExecutorService executor) {
		for (Layer layer : layers) {
			layer.setExecutor(executor);
		}
	}

	@Override
	public final void setDeliverer(final MessageDeliverer deliverer) {
		this.deliverer = deliverer;
	}

	@Override
	public final boolean hasDeliverer() {
		return deliverer != null;
	}

	@Override
	public void destroy() {
		for (Layer layer : layers) {
			layer.destroy();
		}
	}

	private class StackTopAdapter extends AbstractLayer {

		@Override
		public void sendRequest(final Exchange exchange, final Request request) {
			exchange.setRequest(request);
			lower().sendRequest(exchange, request);
		}

		@Override
		public void sendResponse(final Exchange exchange, final Response response) {
			exchange.setResponse(response);
			lower().sendResponse(exchange, response);
		}

		@Override
		public void receiveRequest(final Exchange exchange, final Request request) {
			// if there is no BlockwiseLayer we still have to set it
			if (exchange.getRequest() == null) {
				exchange.setRequest(request);
			}
			if (hasDeliverer()) {
				deliverer.deliverRequest(exchange);
			} else {
				LOGGER.error("Top of CoAP stack has no deliverer to deliver request");
			}
		}

		@Override
		public void receiveResponse(final Exchange exchange, final Response response) {
			if (hasDeliverer()) {
				// notify request that response has arrived
				deliverer.deliverResponse(exchange, response);
			} else {
				LOGGER.error("Top of CoAP stack has no deliverer to deliver response");
			}
		}

		@Override
		public void receiveEmptyMessage(final Exchange exchange, final EmptyMessage message) {
			// When empty messages reach the top of the CoAP stack we can ignore
			// them.
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
			BlockOption block2 = response.getOptions().getBlock2();
			if (block2 == null || !block2.isM()) {
				// for blockwise, the original response shares
				// the MessageObserver with the block response
				response.onComplete();
			}
		}

		@Override
		public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
			outbox.sendEmptyMessage(exchange, message);
		}

	}
}
