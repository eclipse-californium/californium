/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.plugtests.resources;

import static org.eclipse.californium.core.coap.CoAP.ResponseCode.BAD_OPTION;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.CHANGED;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.NOT_ACCEPTABLE;
import static org.eclipse.californium.core.coap.CoAP.ResponseCode.SERVICE_UNAVAILABLE;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_LINK_FORMAT;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.APPLICATION_OCTET_STREAM;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.TEXT_PLAIN;
import static org.eclipse.californium.core.coap.MediaTypeRegistry.UNDEFINED;

import java.security.Principal;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.LinkFormat;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.UriQueryParameter;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.util.LeastRecentlyUsedCache;

/**
 * Echo resource.
 * 
 * Supported query parameter:
 * 
 * <pre>
 * "rlen=n"  : number of bytes used in response.
 * "ack"     : use separate ACK and response.
 * "delay=n" : milliseconds to delay the response.
 * "keep"    : keep post to be read with GET.
 * </pre>
 * 
 * Supported content types:
 * 
 * <ul>
 * <li>{@link MediaTypeRegistry#TEXT_PLAIN}</li>
 * <li>{@link MediaTypeRegistry#APPLICATION_LINK_FORMAT} (only GET)</li>
 * <li>{@link MediaTypeRegistry#APPLICATION_OCTET_STREAM}</li>
 * </ul>
 * 
 * @since 3.2
 */
public class Echo extends CoapResource {

	private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("dd.MMM-HH:mm:ss");

	private static final String RESOURCE_NAME = "echo";
	/**
	 * URI query parameter to specify response length.
	 */
	private static final String URI_QUERY_OPTION_RESPONSE_LENGTH = "rlen";
	/**
	 * URI query parameter to specify ack and separate response.
	 */
	private static final String URI_QUERY_OPTION_ACK = "ack";
	/**
	 * URI query parameter to specify response delay.
	 */
	private static final String URI_QUERY_OPTION_DELAY = "delay";
	/**
	 * URI query parameter to keep the POST for later GET.
	 */
	private static final String URI_QUERY_OPTION_KEEP = "keep";
	/**
	 * Supported query parameter.
	 */
	private static final List<String> SUPPORTED = Arrays.asList(URI_QUERY_OPTION_ACK, URI_QUERY_OPTION_DELAY,
			URI_QUERY_OPTION_RESPONSE_LENGTH, URI_QUERY_OPTION_KEEP);
	/**
	 * Maximum pending delayed responses.
	 */
	private static final int MAX_PENDING_RESPONSES = 1000;

	/**
	 * Maximum message size.
	 */
	private final int maxResourceSize;

	/**
	 * Scheduler for delayed responses.
	 */
	private final ScheduledExecutorService executor;

	private final AtomicInteger pendingResponses = new AtomicInteger();

	private final LeastRecentlyUsedCache<String, Resource> keptPosts = new LeastRecentlyUsedCache<>(100, 500, 6,
			TimeUnit.HOURS);

	/**
	 * Create echo resource.
	 * 
	 * @param maxResourceSize maximum resource size.
	 * @param executor scheduler for delayed responses. {@code null}, if delay
	 *            is not supported.
	 */
	public Echo(int maxResourceSize, ScheduledExecutorService executor) {
		super(RESOURCE_NAME);
		this.executor = executor;
		this.maxResourceSize = maxResourceSize;
		getAttributes().setTitle("Resource, which echo's a POST. POSTs with URI-query 'keep' can later be read by GET");
		getAttributes().addContentType(TEXT_PLAIN);
		getAttributes().addContentType(APPLICATION_OCTET_STREAM);
		getAttributes().addContentType(APPLICATION_LINK_FORMAT);
		keptPosts.setEvictingOnReadAccess(false);
		keptPosts.setUpdatingOnReadAccess(false);
	}

	@Override
	public void add(Resource child) {
		throw new UnsupportedOperationException("Not supported!");
	}

	@Override
	public boolean delete(Resource child) {
		throw new UnsupportedOperationException("Not supported!");
	}

	@Override
	public Resource getChild(String name) {
		synchronized (keptPosts) {
			return keptPosts.get(name);
		}
	}

	@Override // should be used for read-only
	public Collection<Resource> getChildren() {
		synchronized (keptPosts) {
			return keptPosts.values();
		}
	}

	@Override
	public void handleGET(final CoapExchange exchange) {
		Request request = exchange.advanced().getRequest();
		int accept = request.getOptions().getAccept();
		if (accept != UNDEFINED && accept != APPLICATION_LINK_FORMAT) {
			exchange.respond(NOT_ACCEPTABLE);
		} else {
			exchange.respond(ResponseCode.CONTENT, LinkFormat.serializeTree(this), APPLICATION_LINK_FORMAT);
		}
	}

	@Override
	public void handlePOST(final CoapExchange exchange) {

		// get request to read out details
		Request request = exchange.advanced().getRequest();

		int format = request.getOptions().getContentFormat();
		if (format != UNDEFINED && format != TEXT_PLAIN && format != APPLICATION_OCTET_STREAM) {
			exchange.respond(NOT_ACCEPTABLE);
			return;
		}
		int accept = request.getOptions().getAccept();
		if (accept == UNDEFINED) {
			accept = format == UNDEFINED ? APPLICATION_OCTET_STREAM : format;
		} else if (format == UNDEFINED) {
			if (accept != TEXT_PLAIN && accept != APPLICATION_OCTET_STREAM) {
				exchange.respond(NOT_ACCEPTABLE);
				return;
			}
		} else if (accept != format) {
			exchange.respond(NOT_ACCEPTABLE);
			return;
		}

		boolean ack = false;
		boolean keep = false;
		int length = 0;
		int delay = 0;
		try {
			List<String> uriQuery = request.getOptions().getUriQuery();
			UriQueryParameter helper = new UriQueryParameter(uriQuery, SUPPORTED);
			ack = helper.hasParameter(URI_QUERY_OPTION_ACK);
			length = helper.getArgumentAsInteger(URI_QUERY_OPTION_RESPONSE_LENGTH, 0, 0, maxResourceSize);
			delay = helper.getArgumentAsInteger(URI_QUERY_OPTION_DELAY, 0, 0, (int) TimeUnit.SECONDS.toMillis(3600));
			keep = helper.hasParameter(URI_QUERY_OPTION_KEEP);
		} catch (IllegalArgumentException ex) {
			Response response = Response.createResponse(request, BAD_OPTION);
			response.setPayload(ex.getMessage());
			exchange.respond(response);
			return;
		}

		if (ack) {
			exchange.accept();
		}
		byte[] payload = request.getPayload();
		final byte[] responsePayload = length == 0 ? payload : Arrays.copyOf(payload, length);
		if (length > payload.length) {
			Arrays.fill(responsePayload, payload.length, length, (byte) '*');
		}
		if (keep) {
			String principal = getPrincipalName(request);
			if (principal != null) {
				request.setProtectFromOffload();
				Resource child = new Keep(principal, request);
				child.setParent(this);
				synchronized (keptPosts) {
					keptPosts.put(principal, child);
				}
			}
		}
		final int responseFormat = accept;
		if (delay > 0 && executor != null) {
			boolean schedule = false;
			if (pendingResponses.get() < MAX_PENDING_RESPONSES - 1) {
				if (pendingResponses.incrementAndGet() < MAX_PENDING_RESPONSES) {
					schedule = true;
				} else {
					pendingResponses.decrementAndGet();
				}
			}
			if (schedule) {
				Runnable response = new Runnable() {

					@Override
					public void run() {
						exchange.respond(CHANGED, responsePayload, responseFormat);
						pendingResponses.decrementAndGet();
					}
				};
				executor.schedule(response, delay, TimeUnit.MILLISECONDS);
			} else {
				exchange.respond(SERVICE_UNAVAILABLE, "Too many delayed responses pending!");
			}
		} else {
			exchange.respond(CHANGED, responsePayload, responseFormat);
		}
	}

	private static String getPrincipalName(Request request) {
		Principal principal = request.getSourceContext().getPeerIdentity();
		if (principal != null) {
			return principal.getName();
		}
		return null;
	}

	private static class Keep extends CoapResource {

		private final Request post;

		private Keep(String principal, Request post) {
			super(principal);
			this.post = post;
			if (post.getOptions().hasContentFormat()) {
				getAttributes().addContentType(post.getOptions().getContentFormat());
			} else {
				getAttributes().clearContentType();
			}
			getAttributes().addAttribute("time", DATE_FORMAT.format(new Date()));
		}

		@Override
		public void handleGET(final CoapExchange exchange) {
			// get request to read out details
			Request request = exchange.advanced().getRequest();
			int format = post.getOptions().getContentFormat();
			int accept = request.getOptions().getAccept();
			if (accept == UNDEFINED) {
				accept = format == UNDEFINED ? APPLICATION_OCTET_STREAM : format;
			} else if (format == UNDEFINED) {
				if (accept != TEXT_PLAIN && accept != APPLICATION_OCTET_STREAM) {
					exchange.respond(NOT_ACCEPTABLE);
					return;
				}
			} else if (accept != format) {
				exchange.respond(NOT_ACCEPTABLE);
				return;
			}
			exchange.respond(CHANGED, post.getPayload(), accept);
		}

	}

}
