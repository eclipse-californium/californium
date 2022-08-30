/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
 * 
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * 
 * The Eclipse Public License is available at
 *    http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 *    http://www.eclipse.org/org/documents/edl-v10.html.
 * 
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - limit search to 1 query.
 *    Achim Kraus (Bosch Software Innovations GmbH) - use setLength instead of 
 *                                                    delete to remove last character.
 ******************************************************************************/
package org.eclipse.californium.core.server.resources;

import java.util.List;
import java.util.Set;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.WebLink;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;

/**
 * The DiscoveryResource implements CoAP's discovery service.
 * 
 * It is typically accessible over CoAP on the well-known URI:
 * <tt>/.well-known/core</tt>. It responds to GET requests with a list of the
 * server's resources, i.e. links.
 * 
 * Since 3.1, this resource and its children are not longer contained in the
 * discover result.
 */
public class DiscoveryResource extends CoapResource {

	/** The Constant CORE. */
	public static final String CORE = "core";

	/** The root of the server's resource tree */
	private final Resource root;

	/**
	 * Instantiates a new discovery resource.
	 *
	 * @param root the root resource of the server
	 */
	public DiscoveryResource(Resource root) {
		this(CORE, root);
	}

	/**
	 * Instantiates a new discovery resource with the specified name.
	 *
	 * @param name the name
	 * @param root the root resource of the server
	 */
	public DiscoveryResource(String name, Resource root) {
		super(name);
		setVisible(false);
		this.root = root;
	}

	/**
	 * Responds with a list of all resources of the server, i.e. links.
	 * 
	 * @param exchange the exchange
	 */
	@Override
	public void handleGET(CoapExchange exchange) {
		if (exchange.getRequestOptions().hasAccept()
				&& exchange.getRequestOptions().getAccept() != MediaTypeRegistry.APPLICATION_LINK_FORMAT) {
			exchange.respond(ResponseCode.NOT_ACCEPTABLE);
			return;
		}
		List<String> query = exchange.getRequestOptions().getUriQuery();
		if (query.size() > 1) {
			exchange.respond(ResponseCode.BAD_OPTION, "only one search query is supported!",
					MediaTypeRegistry.TEXT_PLAIN);
			return;
		}
		String tree = discoverTree(root, query);
		exchange.respond(ResponseCode.CONTENT, tree, MediaTypeRegistry.APPLICATION_LINK_FORMAT);
	}

	/**
	 * Builds up the list of resources of the specified root resource. Queries
	 * serve as filter and might prevent undesired resources from appearing on
	 * the list.
	 * 
	 * @param root the root resource of the server
	 * @param queries the queries
	 * @return the list of resources as string
	 */
	public String discoverTree(Resource root, List<String> queries) {
		Set<WebLink> subTree = LinkFormat.getSubTree(root, queries);
		return LinkFormat.serialize(subTree);
	}
}
