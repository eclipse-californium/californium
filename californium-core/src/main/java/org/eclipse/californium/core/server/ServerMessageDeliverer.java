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
package org.eclipse.californium.core.server;

import java.net.InetSocketAddress;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Executor;
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

	private final static Logger LOGGER = Logger.getLogger(ServerMessageDeliverer.class.getCanonicalName());

	/* The root of all resources */
	private final Resource root;

	/* The manager of the observe mechanism for this server */
	private ObserveManager observeManager = new ObserveManager();

	/**
	 * Constructs a default message deliverer that delivers requests to the
	 * resources rooted at the specified root.
	 * 
	 * @param root the root resource
	 */
	public ServerMessageDeliverer(Resource root) {
		this.root = root;
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.MessageDeliverer#deliverRequest(ch.inf.vs.californium.network.Exchange)
	 */
	@Override
	public void deliverRequest(final Exchange exchange) {
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
			LOGGER.info("Did not find resource " + path.toString());
			exchange.sendResponse(new Response(ResponseCode.NOT_FOUND));
		}
	}

	/**
	 * Checks whether an observe relationship has to be established or canceled.
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
	private void checkForObserveOption(Exchange exchange, Resource resource) {
		Request request = exchange.getRequest();
		if (request.getCode() != Code.GET) return;

		InetSocketAddress source = new InetSocketAddress(request.getSource(), request.getSourcePort());

		if (request.getOptions().hasObserve() && resource.isObservable()) {
			
			if (request.getOptions().getObserve()==0) {
				// Requests wants to observe and resource allows it :-)
				LOGGER.finer("Initiate an observe relation between " + request.getSource() + ":" + request.getSourcePort() + " and resource " + resource.getURI());
				ObservingEndpoint remote = observeManager.findObservingEndpoint(source);
				ObserveRelation relation = new ObserveRelation(remote, resource, exchange);
				remote.addObserveRelation(relation);
				exchange.setRelation(relation);
				// all that's left is to add the relation to the resource which
				// the resource must do itself if the response is successful
				
			} else if (request.getOptions().getObserve() == 1) {
				// Observe defines 1 for canceling
				ObserveRelation relation = observeManager.getRelation(source, request.getToken());
				if (relation!=null) relation.cancel();
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
	private Resource findResource(List<String> list) {
		LinkedList<String> path = new LinkedList<String>(list);
		Resource current = root;
		while (!path.isEmpty() && current != null) {
			String name = path.removeFirst();
			current = current.getChild(name);
		}
		return current;
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.MessageDeliverer#deliverResponse(ch.inf.vs.californium.network.Exchange, ch.inf.vs.californium.coap.Response)
	 */
	@Override
	public void deliverResponse(Exchange exchange, Response response) {
		if (response == null) throw new NullPointerException();
		if (exchange == null) throw new NullPointerException();
		if (exchange.getRequest() == null) throw new NullPointerException();
		exchange.getRequest().setResponse(response);
	}
}
