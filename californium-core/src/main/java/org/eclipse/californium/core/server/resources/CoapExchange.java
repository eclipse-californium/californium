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
 *    Achim Kraus (Bosch Software Innovations GmbH) - apply source formatter
 ******************************************************************************/
package org.eclipse.californium.core.server.resources;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.elements.DtlsEndpointContext;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.MapBasedEndpointContext;
import org.eclipse.californium.elements.UdpMulticastConnector;

/**
 * The Class CoapExchange represents an exchange of a CoAP request and response
 * and provides a user-friendly API to subclasses of {@link CoapResource} for
 * responding to requests.
 */
public class CoapExchange {

	/* The internal (advanced) exchange. */
	private final Exchange exchange;
	private final Map<String, String> queryParameters;

	/* The destination resource. */
	private final CoapResource resource;

	/* Response option values. */
	private String locationPath = null;
	private String locationQuery = null;
	private String handshakeMode = null;
	private long maxAge = 60;
	private byte[] eTag = null;

	/**
	 * Creates a new CoAP Exchange object for an exchange and resource.
	 * 
	 * @param exchange The message exchange.
	 * @param resource The resource.
	 * @throws NullPointerException if any of the parameters is {@code null}.
	 */
	public CoapExchange(final Exchange exchange, final CoapResource resource) {
		if (exchange == null) {
			throw new NullPointerException("exchange must not be null");
		} else if (resource == null) {
			throw new NullPointerException("resource must not be null");
		}
		this.exchange = exchange;
		this.resource = resource;
		if (getRequestOptions().getURIQueryCount() > 0) {
			this.queryParameters = new HashMap<>();
			for (String param : getRequestOptions().getUriQuery()) {
				addParameter(param);
			}
		} else {
			this.queryParameters = null;
		}
	}

	private void addParameter(final String param) {
		int idx = param.indexOf("=");
		if (idx > 0) {
			queryParameters.put(param.substring(0, idx), param.substring(idx + 1));
		} else {
			queryParameters.put(param, Boolean.TRUE.toString());
		}
	}

	/**
	 * Gets the source socket address of the request.
	 *
	 * @return the source socket address
	 * @since 2.1
	 */
	public InetSocketAddress getSourceSocketAddress() {
		return exchange.getRequest().getSourceContext().getPeerAddress();
	}

	/**
	 * Gets the source address of the request.
	 *
	 * @return the source address
	 */
	public InetAddress getSourceAddress() {
		return exchange.getRequest().getSourceContext().getPeerAddress().getAddress();
	}

	/**
	 * Gets the source port of the request.
	 *
	 * @return the source port
	 */
	public int getSourcePort() {
		return exchange.getRequest().getSourceContext().getPeerAddress().getPort();
	}

	/**
	 * Check, if request is multicast request.
	 * 
	 * @return {@code true}, if request is multicast request, {@code false}, if
	 *         request is unicast request.
	 * @since 2.3
	 */
	public boolean isMulticastRequest() {
		return exchange.getRequest().isMulticast();
	}

	/**
	 * Gets the request code: <tt>GET</tt>, <tt>POST</tt>, <tt>PUT</tt> or
	 * <tt>DELETE</tt>.
	 * 
	 * @return the request code
	 */
	public Code getRequestCode() {
		return exchange.getRequest().getCode();
	}

	/**
	 * Gets the request's options.
	 *
	 * @return the request options
	 */
	public OptionSet getRequestOptions() {
		return exchange.getRequest().getOptions();
	}

	/**
	 * Gets the value of a URI query parameter.
	 * 
	 * @param name The name of the query parameter.
	 * @return The value of the parameter or {@code null} if the request did not
	 *         include a query parameter with the given name.
	 */
	public String getQueryParameter(final String name) {

		if (queryParameters != null) {
			return queryParameters.get(name);
		} else {
			return null;
		}
	}

	/**
	 * Gets the request payload as byte array.
	 *
	 * @return the request payload.
	 */
	public byte[] getRequestPayload() {
		return exchange.getRequest().getPayload();
	}

	/**
	 * Gets the size (amount of bytes) of the request payload. Be aware that this might
	 * differ from the payload string length due to the UTF-8 encoding.
	 *
	 * @return the request payload size.
	 * @since 3.0
	 */
	public int getRequestPayloadSize() {
		return exchange.getRequest().getPayloadSize();
	}

	/**
	 * Gets the request payload as string.
	 *
	 * @return the request payload string
	 */
	public String getRequestText() {
		return exchange.getRequest().getPayloadString();
	}

	/**
	 * Accept the exchange, i.e. send an acknowledgment to the client that the
	 * exchange has arrived and a separate message is being computed and sent
	 * soon. Call this method on an exchange if the computation of a response
	 * might take some time and might trigger a timeout at the client.
	 */
	public void accept() {
		exchange.sendAccept(applyHandshakeMode());
	}

	/**
	 * Reject the exchange if it is impossible to be processed, e.g. if it
	 * carries an unknown critical option. In most cases, it is better to
	 * respond with an error response code to bad requests though.
	 * 
	 * Note: since 2.3, rejects for multicast requests are not sent. (See
	 * {@link UdpMulticastConnector} for receiving multicast requests).
	 * 
	 * @see Exchange#sendReject(EndpointContext)
	 * @since 2.3 rejects for multicast requests are not sent
	 */
	public void reject() {
		exchange.sendReject(applyHandshakeMode());
	}

	/**
	 * Set the Location-Path for the response.
	 * 
	 * @param path the Location-Path value
	 */
	public void setLocationPath(String path) {
		locationPath = path;
	}

	/**
	 * Set the Location-Query for the response.
	 * 
	 * @param query the Location-Query value
	 */
	public void setLocationQuery(String query) {
		locationQuery = query;
	}

	/**
	 * Set the handshake mode for the answer (response, ack or rst).
	 * 
	 * @param handshakeMode the handshake mode.
	 *            {@link DtlsEndpointContext#HANDSHAKE_MODE_AUTO} or
	 *            {@link DtlsEndpointContext#HANDSHAKE_MODE_NONE}
	 * @since 2.1
	 */
	public void setHandshakeMode(String handshakeMode) {
		if (!handshakeMode.equals(DtlsEndpointContext.HANDSHAKE_MODE_AUTO)
				&& !handshakeMode.equals(DtlsEndpointContext.HANDSHAKE_MODE_NONE)) {
			throw new IllegalArgumentException(
					"handshake mode must be either \"" + DtlsEndpointContext.HANDSHAKE_MODE_AUTO + "\" or \""
							+ DtlsEndpointContext.HANDSHAKE_MODE_NONE + "\"!");
		}
		this.handshakeMode = handshakeMode;
	}

	/**
	 * Set the Max-Age for the response body.
	 * 
	 * @param age the Max-Age value
	 */
	public void setMaxAge(long age) {
		maxAge = age;
	}

	/**
	 * Set the ETag for the response.
	 * 
	 * @param tag the ETag of the current response
	 */
	public void setETag(byte[] tag) {
		eTag = tag;
	}

	/**
	 * Respond a overload.
	 * 
	 * Current implementation use 5.03. May be changed, if RFC
	 * "https://draft-ietf-core-too-many-reqs" gets adopted.
	 *
	 * Note: since 2.3, error responses for multicast requests are not sent. (See
	 * {@link UdpMulticastConnector} for receiving multicast requests).
	 * 
	 * @param seconds estimated time in seconds after which the client may retry
	 *            to send requests.
	 * 
	 * @see Exchange#sendResponse(Response)
	 * @since 2.3 error responses for multicast requests are not sent
	 */
	public void respondOverload(int seconds) {
		setMaxAge(seconds);
		respond(ResponseCode.SERVICE_UNAVAILABLE);
	}

	/**
	 * Respond the specified response code and no payload. Allowed response
	 * codes are:
	 * <ul>
	 * <li>GET: Content (2.05), Valid (2.03)</li>
	 * <li>POST: Created (2.01), Changed (2.04), Deleted (2.02)</li>
	 * <li>PUT: Created (2.01), Changed (2.04)</li>
	 * <li>DELETE: Deleted (2.02)</li>
	 * </ul>
	 * 
	 * Fills in {@link #locationPath}, {@link #locationQuery}, {@link #maxAge},
	 * and/or {@link #eTag}, if set before.
	 *
	 * Note: since 2.3, error responses for multicast requests are not sent. (See
	 * {@link UdpMulticastConnector} for receiving multicast requests).
	 * 
	 * @param code the response code
	 * 
	 * @see Exchange#sendResponse(Response)
	 * @since 2.3 error responses for multicast requests are not sent
	 */
	public void respond(ResponseCode code) {
		respond(new Response(code));
	}

	/**
	 * Respond with response code 2.05 (Content) and the specified payload.
	 *
	 * Fills in {@link #locationPath}, {@link #locationQuery}, {@link #maxAge},
	 * and/or {@link #eTag}, if set before.
	 * 
	 * @param payload the payload as string
	 */
	public void respond(String payload) {
		respond(ResponseCode.CONTENT, payload);
	}

	/**
	 * Respond with the specified response code and the specified payload.
	 * <ul>
	 * <li>GET: Content (2.05), Valid (2.03)</li>
	 * <li>POST: Created (2.01), Changed (2.04), Deleted (2.02)</li>
	 * <li>PUT: Created (2.01), Changed (2.04)</li>
	 * <li>DELETE: Deleted (2.02)</li>
	 * </ul>
	 *
	 * Fills in {@link #locationPath}, {@link #locationQuery}, {@link #maxAge},
	 * and/or {@link #eTag}, if set before.
	 * 
	 * Note: since 2.3, error responses for multicast requests are not sent. (See
	 * {@link UdpMulticastConnector} for receiving multicast requests).
	 * 
	 * @param code the response code
	 * @param payload the payload
	 * 
	 * @see Exchange#sendResponse(Response)
	 * @since 2.3 error responses for multicast requests are not sent
	 */
	public void respond(ResponseCode code, String payload) {
		Response response = new Response(code);
		response.setPayload(payload);
		response.getOptions().setContentFormat(MediaTypeRegistry.TEXT_PLAIN);
		respond(response);
	}

	/**
	 * Respond with the specified response code and the specified payload.
	 * <ul>
	 * <li>GET: Content (2.05), Valid (2.03)</li>
	 * <li>POST: Created (2.01), Changed (2.04), Deleted (2.02)</li>
	 * <li>PUT: Created (2.01), Changed (2.04)</li>
	 * <li>DELETE: Deleted (2.02)</li>
	 * </ul>
	 *
	 * Fills in {@link #locationPath}, {@link #locationQuery}, {@link #maxAge},
	 * and/or {@link #eTag}, if set before.
	 * 
	 * Note: since 2.3, error responses for multicast requests are not sent. (See
	 * {@link UdpMulticastConnector} for receiving multicast requests).
	 *
	 * @param code the response code
	 * @param payload the payload
	 * 
	 * @see Exchange#sendResponse(Response)
	 * @since 2.3 error responses for multicast requests are not sent
	 */
	public void respond(ResponseCode code, byte[] payload) {
		Response response = new Response(code);
		response.setPayload(payload);
		respond(response);
	}

	/**
	 * Respond with the specified response code and the specified payload.
	 * <ul>
	 * <li>GET: Content (2.05), Valid (2.03)</li>
	 * <li>POST: Created (2.01), Changed (2.04), Deleted (2.02)</li>
	 * <li>PUT: Created (2.01), Changed (2.04)</li>
	 * <li>DELETE: Deleted (2.02)</li>
	 * </ul>
	 *
	 * Fills in {@link #locationPath}, {@link #locationQuery}, {@link #maxAge},
	 * and/or {@link #eTag}, if set before.
	 * 
	 * Note: since 2.3, error responses for multicast requests are not sent. (See
	 * {@link UdpMulticastConnector} for receiving multicast requests).
	 * 
	 * @param code the response code
	 * @param payload the payload
	 * @param contentFormat the Content-Format of the payload
	 * 
	 * @see Exchange#sendResponse(Response)
	 * @since 2.3 error responses for multicast requests are not sent
	 */
	public void respond(ResponseCode code, byte[] payload, int contentFormat) {
		Response response = new Response(code);
		response.setPayload(payload);
		response.getOptions().setContentFormat(contentFormat);
		respond(response);
	}

	/**
	 * Respond with the specified response code and the specified payload.
	 * <ul>
	 * <li>GET: Content (2.05), Valid (2.03)</li>
	 * <li>POST: Created (2.01), Changed (2.04), Deleted (2.02)</li>
	 * <li>PUT: Created (2.01), Changed (2.04)</li>
	 * <li>DELETE: Deleted (2.02)</li>
	 * </ul>
	 * 
	 * Fills in {@link #locationPath}, {@link #locationQuery}, {@link #maxAge},
	 * and/or {@link #eTag}, if set before.
	 *
	 * Note: since 2.3, error responses for multicast requests are not sent. (See
	 * {@link UdpMulticastConnector} for receiving multicast requests).
	 *
	 * @param code the response code
	 * @param payload the payload
	 * @param contentFormat the Content-Format of the payload
	 * 
	 * @see Exchange#sendResponse(Response)
	 * @since 2.3 error responses for multicast requests are not sent
	 */
	public void respond(ResponseCode code, String payload, int contentFormat) {
		Response response = new Response(code);
		response.setPayload(payload);
		response.getOptions().setContentFormat(contentFormat);
		respond(response);
	}

	/**
	 * Respond with the specified response.
	 * 
	 * Fills in {@link #locationPath}, {@link #locationQuery}, {@link #maxAge},
	 * and/or {@link #eTag}, if set before.
	 * 
	 * Note: since 2.3, error responses for multicast requests are not sent. (See
	 * {@link UdpMulticastConnector} for receiving multicast requests).
	 * 
	 * @param response the response
	 * 
	 * @see Exchange#sendResponse(Response)
	 * @since 2.3 error responses for multicast requests are not sent
	 */
	public void respond(Response response) {
		if (response == null)
			throw new NullPointerException();

		// set the response options configured through the CoapExchange API
		if (locationPath != null)
			response.getOptions().setLocationPath(locationPath);
		if (locationQuery != null)
			response.getOptions().setLocationQuery(locationQuery);
		if (maxAge != 60)
			response.getOptions().setMaxAge(maxAge);
		if (eTag != null) {
			response.getOptions().clearETags();
			response.getOptions().addETag(eTag);
		}

		resource.checkObserveRelation(exchange, response);
		if (response.getDestinationContext() == null) {
			response.setDestinationContext(applyHandshakeMode());
		}
		exchange.sendResponse(response);
	}

	private EndpointContext applyHandshakeMode() {
		EndpointContext context = exchange.getCurrentRequest().getSourceContext();
		if (handshakeMode != null && context.get(DtlsEndpointContext.KEY_HANDSHAKE_MODE) == null) {
			context = MapBasedEndpointContext.addEntries(context, DtlsEndpointContext.KEY_HANDSHAKE_MODE,
					handshakeMode);
		}
		return context;
	}

	/**
	 * Provides access to the internal Exchange object.
	 * 
	 * @return the Exchange object
	 */
	public Exchange advanced() {
		return exchange;
	}
}
