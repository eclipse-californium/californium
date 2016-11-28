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
package org.eclipse.californium.core.server.resources;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.coap.OptionSet;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;

/**
 * The Class CoapExchange represents an exchange of a CoAP request and response
 * and provides a user-friendly API to subclasses of {@link CoapResource} for
 * responding to requests.
 */
public class CoapExchange {
	
	/* The internal (advanced) exchange. */
	private Exchange exchange;
	private Map<String, String> queryParameters;

	/* The destination resource. */
	private CoapResource resource;
	
	/* Response option values. */
	private String locationPath = null;
	private String locationQuery = null;
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
		parseUriQuery();
	}

	private void parseUriQuery() {
		if (getRequestOptions().getURIQueryCount() > 0) {
			queryParameters = new HashMap<>();
			for (String param : getRequestOptions().getUriQuery()) {
				addParameter(param);
			}
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
	 * Gets the source address of the request.
	 *
	 * @return the source address
	 */
	public InetAddress getSourceAddress() {
		return exchange.getRequest().getSource();
	}
	
	/**
	 * Gets the source port of the request.
	 *
	 * @return the source port
	 */
	public int getSourcePort() {
		return exchange.getRequest().getSourcePort();
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
	 * @return The value of the parameter or {@code null} if the request did not include
	 *         a query parameter with the given name.
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
	 * @return the request payload
	 */
	public byte[] getRequestPayload() {
		return exchange.getRequest().getPayload();
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
		exchange.sendAccept();
	}
	
	/**
	 * Reject the exchange if it is impossible to be processed, e.g. if it
	 * carries an unknown critical option. In most cases, it is better to
	 * respond with an error response code to bad requests though.
	 */
	public void reject() {
		exchange.sendReject();
	}
	
	/**
	 * Set the Location-Path for the response.
	 * @param path the Location-Path value
	 */
	public void setLocationPath(String path) {
		locationPath = path;
	}
	
	/**
	 * Set the Location-Query for the response.
	 * @param query the Location-Query value
	 */
	public void setLocationQuery(String query) {
		locationQuery = query;
	}
	
	/**
	 * Set the Max-Age for the response body.
	 * @param age the Max-Age value
	 */
	public void setMaxAge(long age) {
		maxAge = age;
	}

	/**
	 * Set the ETag for the response.
	 * @param tag the ETag of the current response
	 */
	public void setETag(byte[] tag) {
		eTag = tag;
	}
	
	/**
	 * Respond the specified response code and no payload. Allowed response codes are:
	 * <ul>
	 *   <li>GET: Content (2.05), Valid (2.03)</li>
	 *   <li>POST: Created (2.01), Changed (2.04), Deleted (2.02) </li>
	 *   <li>PUT: Created (2.01), Changed (2.04)</li>
	 *   <li>DELETE: Deleted (2.02)</li>
	 * </ul>
	 *
	 * @param code the response code
	 */
	public void respond(ResponseCode code) {
		respond(new Response(code));
	}
	
	/**
	 * Respond with response code 2.05 (Content) and the specified payload.
	 *
	 * @param payload the payload as string
	 */
	public void respond(String payload) {
		respond(ResponseCode.CONTENT, payload);
	}
	
	/**
	 * Respond with the specified response code and the specified payload.
	 * <ul>
	 *   <li>GET: Content (2.05), Valid (2.03)</li>
	 *   <li>POST: Created (2.01), Changed (2.04), Deleted (2.02) </li>
	 *   <li>PUT: Created (2.01), Changed (2.04)</li>
	 *   <li>DELETE: Deleted (2.02)</li>
	 * </ul>
	 *
	 * @param code the response code
	 * @param payload the payload
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
	 *   <li>GET: Content (2.05), Valid (2.03)</li>
	 *   <li>POST: Created (2.01), Changed (2.04), Deleted (2.02) </li>
	 *   <li>PUT: Created (2.01), Changed (2.04)</li>
	 *   <li>DELETE: Deleted (2.02)</li>
	 * </ul>
	 *
	 * @param code the response code
	 * @param payload the payload
	 */
	public void respond(ResponseCode code, byte[] payload) {
		Response response = new Response(code);
		response.setPayload(payload);
		respond(response);
	}

	/**
	 * Respond with the specified response code and the specified payload.
	 * <ul>
	 *   <li>GET: Content (2.05), Valid (2.03)</li>
	 *   <li>POST: Created (2.01), Changed (2.04), Deleted (2.02) </li>
	 *   <li>PUT: Created (2.01), Changed (2.04)</li>
	 *   <li>DELETE: Deleted (2.02)</li>
	 * </ul>
	 *
	 * @param code the response code
	 * @param payload the payload
	 * @param contentFormat the Content-Format of the payload
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
	 *   <li>GET: Content (2.05), Valid (2.03)</li>
	 *   <li>POST: Created (2.01), Changed (2.04), Deleted (2.02) </li>
	 *   <li>PUT: Created (2.01), Changed (2.04)</li>
	 *   <li>DELETE: Deleted (2.02)</li>
	 * </ul>
	 *
	 * @param code the response code
	 * @param payload the payload
	 * @param contentFormat the Content-Format of the payload
	 */
	public void respond(ResponseCode code, String payload, int contentFormat) {
		Response response = new Response(code);
		response.setPayload(payload);
		response.getOptions().setContentFormat(contentFormat);
		respond(response);
	}
	
	/**
	 * Respond with the specified response.
	 * @param response the response
	 */
	public void respond(Response response) {
		if (response == null) throw new NullPointerException();
		
		// set the response options configured through the CoapExchange API
		if (locationPath != null) response.getOptions().setLocationPath(locationPath);
		if (locationQuery != null) response.getOptions().setLocationQuery(locationQuery);
		if (maxAge != 60) response.getOptions().setMaxAge(maxAge);
		if (eTag != null) {
			response.getOptions().clearETags();
			response.getOptions().addETag(eTag);
		}
		
		resource.checkObserveRelation(exchange, response);
		
		exchange.sendResponse(response);
	}
	
	/**
	 * Provides access to the internal Exchange object.
	 * @return the Exchange object
	 */
	public Exchange advanced() {
		return exchange;
	}
}
