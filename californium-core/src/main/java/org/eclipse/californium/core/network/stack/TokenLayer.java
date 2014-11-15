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

import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;


/**
 * Doesn't do much yet except for setting a simple token. Notice that empty
 * tokens must be represented as byte array of length 0 (not null).
 */
public class TokenLayer extends AbstractLayer {
	
	private AtomicInteger counter;
	
	public TokenLayer(NetworkConfig config) {
		if (config.getBoolean(NetworkConfig.Keys.USE_RANDOM_TOKEN_START))
			counter = new AtomicInteger(new Random().nextInt());
		else counter = new AtomicInteger(0);
	}
	
	@Override
	public void sendRequest(Exchange exchange, Request request) {
		if (request.getToken() == null)
			request.setToken(createNewToken());
		super.sendRequest(exchange, request);
	}

	@Override
	public void sendResponse(Exchange exchange, Response response) {
		// A response must have the same token as the request it belongs to. If
		// the token is empty, we must use a byte array of length 0.
		if (response.getToken() == null) {
			response.setToken(exchange.getCurrentRequest().getToken());
		}
		super.sendResponse(exchange, response);
	}

	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.sendEmptyMessage(exchange, message);
	}

	@Override
	public void receiveRequest(Exchange exchange, Request request) {
		if (exchange.getCurrentRequest().getToken() == null)
			throw new NullPointerException("Received requests's token cannot be null, use byte[0] for empty tokens");
		super.receiveRequest(exchange, request);
	}

	@Override
	public void receiveResponse(Exchange exchange, Response response) {
		if (response.getToken() == null)
			throw new NullPointerException("Received response's token cannot be null, use byte[0] for empty tokens");
		super.receiveResponse(exchange, response);
	}

	@Override
	public void receiveEmptyMessage(Exchange exchange, EmptyMessage message) {
		super.receiveEmptyMessage(exchange, message);
	}
	
	/**
	 * Creates a new token.
	 * @return the new token
	 */
	private byte[] createNewToken() {
		int token = counter.incrementAndGet();
		return new byte[] { (byte) (token>>>24), (byte) (token>>>16), (byte) (token>>>8), (byte) token}; 
	}
}
