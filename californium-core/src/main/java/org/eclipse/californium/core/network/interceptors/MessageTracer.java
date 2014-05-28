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
package org.eclipse.californium.core.network.interceptors;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.CoAPEndpoint;

/**
 * The MessageLogger logs all incoming and outgoing messages. The MessageLogger
 * is used by an {@link CoAPEndpoint} and is located between the serializer/parser
 * and the matcher. Each message comes or goes to the connector is logged.
 */
public class MessageTracer implements MessageInterceptor {
	
	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.MessageIntercepter#sendRequest(ch.inf.vs.californium.coap.Request)
	 */
	@Override
	public void sendRequest(Request request) {
		System.out.println(String.format("----------------------------------------------------------------\n" +
										 "%s:%d <== req %s\n" +
										 "----------------------------------------------------------------",
				request.getDestination(), request.getDestinationPort(), request));
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.MessageIntercepter#sendResponse(ch.inf.vs.californium.coap.Response)
	 */
	@Override
	public void sendResponse(Response response) {
		System.out.println(String.format("----------------------------------------------------------------\n" +
										 "%s:%d <== res %s\n" +
										 "----------------------------------------------------------------",
				response.getDestination(), response.getDestinationPort(), response));
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.MessageIntercepter#sendEmptyMessage(ch.inf.vs.californium.coap.EmptyMessage)
	 */
	@Override
	public void sendEmptyMessage(EmptyMessage message) {
		System.out.println(String.format("----------------------------------------------------------------\n" +
										 "%s:%d <== emp %s\n" +
										 "----------------------------------------------------------------",
				message.getDestination(), message.getDestinationPort(), message));
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.MessageIntercepter#receiveRequest(ch.inf.vs.californium.coap.Request)
	 */
	@Override
	public void receiveRequest(Request request) {
		System.out.println(String.format("----------------------------------------------------------------\n" +
										 "%s:%d ==> req %s\n" +
										 "----------------------------------------------------------------",
				request.getSource(), request.getSourcePort(), request));
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.MessageIntercepter#receiveResponse(ch.inf.vs.californium.coap.Response)
	 */
	@Override
	public void receiveResponse(Response response) {
		System.out.println(String.format("----------------------------------------------------------------\n" +
										 "%s:%d ==> res %s\n" +
										 "----------------------------------------------------------------",
				response.getSource(), response.getSourcePort(), response));
	}

	/* (non-Javadoc)
	 * @see ch.inf.vs.californium.network.MessageIntercepter#receiveEmptyMessage(ch.inf.vs.californium.coap.EmptyMessage)
	 */
	@Override
	public void receiveEmptyMessage(EmptyMessage message) {
		System.out.println(String.format("----------------------------------------------------------------\n" +
										 "%s:%d ==> emp %s\n" +
										 "----------------------------------------------------------------",
				message.getSource(), message.getSourcePort(), message));
	}
	
}
