/********************************************************************************
 * Copyright (c) 2024 Contributors to the Eclipse Foundation
 * 
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 * 
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * https://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v1.0 which is available at
 * https://www.eclipse.org/org/documents/edl-v10.php.
 * 
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 ********************************************************************************/
package org.eclipse.californium.cloud.s3.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.BAD_OPTION;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.FORBIDDEN;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_CBOR;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JAVASCRIPT;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_JSON;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_LINK_FORMAT;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_OCTET_STREAM;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_XML;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.util.Arrays;
import java.util.List;

import org.eclipse.californium.cloud.option.TimeOption;
import org.eclipse.californium.cloud.resources.ProtectedCoapResource;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClient;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyClientProvider;
import org.eclipse.californium.cloud.s3.proxy.S3ProxyRequest;
import org.eclipse.californium.cloud.s3.util.DomainPrincipalInfo;
import org.eclipse.californium.cloud.util.PrincipalInfo;
import org.eclipse.californium.cloud.util.PrincipalInfo.Type;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.config.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Generic S3 proxy resource.
 * 
 * @since 3.12
 */
public class S3ProxyResource extends ProtectedCoapResource {

	private static final Logger LOGGER = LoggerFactory.getLogger(S3ProxyResource.class);

	/**
	 * URI query parameter to specify the ACL for S3.
	 */
	public static final String URI_QUERY_OPTION_ACL = "acl";
	/**
	 * Supported query parameter.
	 */
	private static final List<String> SUPPORTED = Arrays.asList(URI_QUERY_OPTION_ACL);

	private final S3ProxyClientProvider s3Clients;

	private final int pathStartIndex;

	private final int[] CONTENT_TYPES = { TEXT_PLAIN, APPLICATION_OCTET_STREAM, APPLICATION_JSON, APPLICATION_CBOR,
			APPLICATION_XML, APPLICATION_JAVASCRIPT, APPLICATION_LINK_FORMAT };

	/**
	 * Creates s3 proxy resource.
	 * 
	 * @param name name of proxy resource
	 * @param pathStartIndex start index of mapped path
	 * @param config configuration
	 * @param s3Clients S3 clients
	 */
	public S3ProxyResource(String name, int pathStartIndex, Configuration config, S3ProxyClientProvider s3Clients) {
		super(name, Type.DEVICE, Type.ANONYMOUS_DEVICE, Type.APPL_AUTH_DEVICE);
		if (s3Clients == null) {
			throw new NullPointerException("s3client must not be null!");
		}
		Arrays.sort(CONTENT_TYPES);
		getAttributes().setTitle("S3Proxy Resource, generic S3 access.");
		getAttributes().addContentTypes(CONTENT_TYPES);
		this.s3Clients = s3Clients;
		this.pathStartIndex = pathStartIndex;
	}

	@Override
	protected ResponseCode checkOperationPermission(PrincipalInfo info, Exchange exchange, boolean write) {
		if (write) {
			return FORBIDDEN;
		} else {
			return null;
		}
	}

	/*
	 * Override the default behavior so that requests to sub resources
	 * (typically /{path}/{s3-key}) are handled by /s3 resource.
	 */
	@Override
	public Resource getChild(String name) {
		return this;
	}

	@Override
	public void handleGET(final CoapExchange exchange) {
		Request request = exchange.advanced().getRequest();
		int accept = request.getOptions().getAccept();
		if (accept != UNDEFINED && Arrays.binarySearch(CONTENT_TYPES, accept) < 0) {
			Response response = new Response(NOT_ACCEPTABLE);
			exchange.respond(response);
			return;
		}
		try {
			request.getOptions().getUriQueryParameter(SUPPORTED);
			LOGGER.info("URI-Query: {}", request.getOptions().getUriQuery());
			List<Option> others = request.getOptions().getOthers();
			if (!others.isEmpty()) {
				LOGGER.info("Other options: {}", others);
			}
		} catch (IllegalArgumentException ex) {
			Response response = new Response(BAD_OPTION);
			response.setPayload(ex.getMessage());
			exchange.respond(response);
			return;
		}
		final TimeOption timeOption = TimeOption.getMessageTime(request);
		final TimeOption responseTimeOption = timeOption.adjust();

		final String domain = DomainPrincipalInfo.getDomain(getPrincipal(exchange));
		S3ProxyClient s3Client = s3Clients.getProxyClient(domain);
		S3ProxyRequest s3ReadRequest = S3ProxyRequest.builder(request).pathStartIndex(pathStartIndex).build();
		s3Client.get(s3ReadRequest, (Response s3response) -> {
			// respond with time?
			if (responseTimeOption != null) {
				s3response.getOptions().addOtherOption(responseTimeOption);
			}
			exchange.respond(s3response);
		});
	}

	@Override
	public void handlePUT(final CoapExchange exchange) {
		Request request = exchange.advanced().getRequest();

		int format = request.getOptions().getContentFormat();
		if (format != UNDEFINED && Arrays.binarySearch(CONTENT_TYPES, format) < 0) {
			Response response = new Response(NOT_ACCEPTABLE);
			exchange.respond(response);
			return;
		}

		try {
			request.getOptions().getUriQueryParameter(SUPPORTED);
			LOGGER.info("URI-Query: {}", request.getOptions().getUriQuery());
			List<Option> others = request.getOptions().getOthers();
			if (!others.isEmpty()) {
				LOGGER.info("Other options: {}", others);
			}
		} catch (IllegalArgumentException ex) {
			Response response = new Response(BAD_OPTION);
			response.setPayload(ex.getMessage());
			exchange.respond(response);
			return;
		}

		final TimeOption timeOption = TimeOption.getMessageTime(request);
		final TimeOption responseTimeOption = timeOption.adjust();
		final String domain = DomainPrincipalInfo.getDomain(getPrincipal(exchange));

		S3ProxyClient s3Client = s3Clients.getProxyClient(domain);
		S3ProxyRequest s3ReadRequest = S3ProxyRequest.builder(request).build();
		s3Client.put(s3ReadRequest, (Response s3response) -> {
			// respond with time?
			if (responseTimeOption != null) {
				s3response.getOptions().addOtherOption(responseTimeOption);
			}
			exchange.respond(s3response);
		});
	}
}
