/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 ******************************************************************************/
package org.eclipse.californium.core.network.interceptors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;

/**
 * The MessageTracer logs all incoming and outgoing messages. MessageInterceptor
 * are located between the serializer/parser and the matcher. Each message comes
 * or goes through a connector is logged.
 */
public class MessageTracer implements MessageInterceptor {

	private final static Logger LOGGER = LoggerFactory.getLogger(MessageTracer.class);

	@Override
	public void sendRequest(Request request) {
		LOGGER.info("{} <== req {}", request.getDestinationContext(), request);
	}

	@Override
	public void sendResponse(Response response) {
		LOGGER.info("{} <== res {}", response.getDestinationContext(), response);
	}

	@Override
	public void sendEmptyMessage(EmptyMessage message) {
		LOGGER.info("{} <== emp {}", message.getDestinationContext(), message);
	}

	@Override
	public void receiveRequest(Request request) {
		LOGGER.info("{} ==> req {}", request.getSourceContext(), request);
	}

	@Override
	public void receiveResponse(Response response) {
		LOGGER.info("{} ==> res {}", response.getSourceContext(), response);
	}

	@Override
	public void receiveEmptyMessage(EmptyMessage message) {
		LOGGER.info("{} ==> emp {}", message.getSourceContext(), message);
	}
}
