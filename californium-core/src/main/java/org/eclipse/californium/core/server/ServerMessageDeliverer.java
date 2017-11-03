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
package org.eclipse.californium.core.server;

import java.net.InetSocketAddress;
import java.util.Deque;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.observe.ObserveManager;
import org.eclipse.californium.core.observe.ObserveRelation;
import org.eclipse.californium.core.observe.ObservingEndpoint;
import org.eclipse.californium.core.server.resources.Resource;

/**
 * The ServerMessageDeliverer delivers requests to corresponding resources and
 * responses to corresponding requests.
 */
public class ServerMessageDeliverer implements MessageDeliverer {

	private static final Logger LOGGER = Logger.getLogger(ServerMessageDeliverer.class.getCanonicalName());

	/* The root of all resources */
	private final Resource root;

	/* The manager of the observe mechanism for this server */
	private final ObserveManager observeManager = new ObserveManager();

	/**
	 * Constructs a default message deliverer that delivers requests to the
	 * resources rooted at the specified root.
	 * 
	 * @param root the root resource
	 */
	public ServerMessageDeliverer(final Resource root) {
		this.root = root;
	}

	/**
	 * Delivers an inbound CoAP request to an appropriate resource.
	 * <p>
	 * This method first invokes {@link #preDeliverRequest(Exchange)}.
	 * The request is considered <em>processed</em> if the
	 * <em>preDeliverRequest</em> method returned {@code true}.
	 * <p>
	 * Otherwise, this method
	 * <ol>
	 * <li>tries to {@linkplain #findResource(List) find a matching resource},</li>
	 * <li>handle a GET request's observe option and </li>
	 * <li>deliver the request to the resource for processing.</li>
	 * </ol>
	 * 
	 * @param exchange The exchange containing the inbound request.
	 * @throws NullPointerException if exchange is {@code null}.
	 */
	@Override
	public final void deliverRequest(final Exchange exchange) {
		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		}
		boolean processed = preDeliverRequest(exchange);
		if (!processed) {
			Request request = exchange.getRequest();
			List<String> path = request.getOptions().getUriPath();
			final Resource resource = findResource(path);
			if (resource != null) {
				checkForObserveOption(exchange, resource);

				// Get the executor and let it process the request
				Executor executor = resource.getExecutor();
				if (executor != null) {
					exchange.setCustomExecutor();
					executor.execute(new Runnable() {
						public void run() {
							resource.handleRequest(exchange);
						} });
				} else {
					resource.handleRequest(exchange);
				}
			} else {
				LOGGER.log(Level.INFO, "Did not find resource {0} requested by {1}:{2}",
						new Object[]{path, request.getSource(), request.getSourcePort()});
				exchange.sendResponse(new Response(ResponseCode.NOT_FOUND));
			}
		}
	}

	/**
	 * Invoked by the <em>deliverRequest</em> before the request gets processed.
	 * <p>
	 * Subclasses may override this method in order to replace the default request handling logic
	 * or to modify or add headers etc before the request gets processed.
	 * <p>
	 * This default implementation returns {@code false}.
	 * 
	 * @param exchange The exchange for the incoming request.
	 * @return {@code true} if the request has already been processed by this method and thus
	 *         should not be delivered to a matching resource anymore.
	 */
	protected boolean preDeliverRequest(final Exchange exchange) {
		return false;
	}

	/**
	 * Checks whether an observe relationship has to be established or canceled.
	 * <p>
	 * This is done here to have a server-global observeManager that holds the
	 * set of remote endpoints for all resources. This global knowledge is required
	 * for efficient orphan handling.
	 * 
	 * @param exchange
	 *            the exchange of the current request
	 * @param resource
	 *            the target resource
	 * @param path
	 *            the path to the resource
	 */
	protected final void checkForObserveOption(final Exchange exchange, final Resource resource) {

		Request request = exchange.getRequest();
		if (request.getCode() == Code.GET && request.getOptions().hasObserve() && resource.isObservable()) {

			InetSocketAddress source = new InetSocketAddress(request.getSource(), request.getSourcePort());

			if (request.getOptions().getObserve() == 0) {
				// Requests wants to observe and resource allows it :-)
				LOGGER.log(Level.FINER,
						"Initiate an observe relation between {0}:{1} and resource {2}",
						new Object[]{request.getSource(), request.getSourcePort(), resource.getURI()});
				ObservingEndpoint remote = observeManager.findObservingEndpoint(source);
				ObserveRelation relation = new ObserveRelation(remote, resource, exchange);
				remote.addObserveRelation(relation);
				exchange.setRelation(relation);
				// all that's left is to add the relation to the resource which
				// the resource must do itself if the response is successful

			} else if (request.getOptions().getObserve() == 1) {
				// Observe defines 1 for canceling
				ObserveRelation relation = observeManager.getRelation(source, request.getToken());
				if (relation != null) {
					relation.cancel();
				}
			}
		}
	}

	/**
	 * Searches in the resource tree for the specified path. A parent resource
	 * may accept requests to subresources, e.g., to allow addresses with
	 * wildcards like <code>coap://example.com:5683/devices/*</code>
	 * 
	 * @param list the path as list of resource names
	 * @return the resource or null if not found
	 */
	protected final Resource findResource(final List<String> list) {
		Deque<String> path = new LinkedList<String>(list);
		Resource current = root;
		while (!path.isEmpty() && current != null) {
			String name = path.removeFirst();
			current = current.getChild(name);
		}
		return current;
	}

	/**
	 * Delivers an inbound CoAP response message to its corresponding request.
	 * <p>
	 * This method first invokes {@link #preDeliverResponse(Exchange, Response)}.
	 * The response is considered <em>processed</em> if the
	 * <em>preDeliverResponse</em> method returned {@code true}.
	 * <p>
* 	 * Otherwise, this method delivers the response to the corresponding request.
	 * 
	 * @param exchange
	 *            The exchange containing the originating CoAP request.
	 * @param response
	 *            The inbound CoAP response message.
	 * @throws NullPointerException if exchange or response are {@code null}.
	 * @throws IllegalArgumentException if the exchange does not contain a request.
	 */
	@Override
	public final void deliverResponse(final Exchange exchange, final Response response) {
		if (response == null) {
			throw new NullPointerException("Response must not be null");
		} else if (exchange == null) {
			throw new NullPointerException("Exchange must not be null");
		} else if (exchange.getRequest() == null) {
			throw new IllegalArgumentException("Exchange does not contain request");
		} else {
			boolean processed = preDeliverResponse(exchange, response);
			if (!processed) {
				exchange.getRequest().setResponse(response);
			}
		}
	}

	/**
	 * Invoked by the <em>deliverResponse</em> method before the response is delivered to the
	 * corresponding request.
	 * <p>
	 * Subclasses may override this method in order to replace the default response handling logic
	 * or to modify or add headers etc before the response is delivered to the request.
	 * <p>
	 * The response is delivered to the request if and only if the exchange's request does not
	 * contain a <em>response</em> when this method returns.
	 * <p>
	 * This default implementation returns {@code false}.
	 * 
	 * @param exchange The exchange containing the request that the incoming response belongs to.
	 * @param response The incoming response.
	 * @return {@code true} if the response has been processed by this method and thus should
	 *         not be delivered to the corresponding request anymore.
	 */
	protected boolean preDeliverResponse(final Exchange exchange, final Response response) {
		return false;
	}
}
