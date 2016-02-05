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
package org.eclipse.californium.core.network.interceptors;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

/**
 * The MessageTracer logs all incoming and outgoing messages. MessageInterceptor
 * are located between the serializer/parser and the matcher. Each message comes
 * or goes through a connector is logged.
 */
public class MessageTracer implements MessageInterceptor {
	
	private final static Logger LOGGER = Logger.getLogger(MessageTracer.class.getCanonicalName());
	
	@Override
	public void sendRequest(Request request) {
		LOGGER.log(Level.INFO, "{0}:{1} <== req {2}", new Object[]{request.getDestination(), request.getDestinationPort(), request});
	}
	
	@Override
	public void sendResponse(Response response) {
		LOGGER.log(Level.INFO, "{0}:{1} <== res {2}", new Object[]{response.getDestination(), response.getDestinationPort(), response});
	}
	
	@Override
	public void sendEmptyMessage(EmptyMessage message) {
		LOGGER.log(Level.INFO, "{0}:{1} <== emp {2}", new Object[]{message.getDestination(), message.getDestinationPort(), message});
	}
	
	@Override
	public void receiveRequest(Request request) {
		LOGGER.log(Level.INFO, "{0}:{1} ==> req {2}", new Object[]{request.getSource(), request.getSourcePort(), request});
	}
	
	@Override
	public void receiveResponse(Response response) {
		LOGGER.log(Level.INFO, "{0}:{1} ==> res {2}", new Object[]{response.getSource(), response.getSourcePort(), response});
	}	

	@Override
	public void receiveEmptyMessage(EmptyMessage message) {
		LOGGER.log(Level.INFO, "{0}:{1} ==> emp {2}", new Object[]{message.getSource(), message.getSourcePort(), message});
	}
}
