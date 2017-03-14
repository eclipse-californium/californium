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
package org.eclipse.californium.core.test.lockstep;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;

/**
 * A message interceptor for tracing messages from the viewpoint of a CoAP client.
 *
 */
public final class ClientBlockwiseInterceptor extends BlockwiseInterceptor implements MessageInterceptor {

	@Override
	public synchronized void sendRequest(final Request request) {
		buffer.append(System.lineSeparator());
		appendRequestDetails(request);
		buffer.append("    ----->");
	}

	@Override
	public synchronized void sendResponse(final Response response) {
		buffer.append("ERROR: Server received ").append(response).append(System.lineSeparator());
	}

	@Override
	public synchronized void sendEmptyMessage(final EmptyMessage message) {
		buffer.append(System.lineSeparator());
		appendEmptyMessageDetails(message);
		buffer.append("   ----->");
	}

	@Override
	public synchronized void receiveRequest(final Request request) {
		buffer.append(System.lineSeparator()).append("ERROR: Server sent ").append(request).append(System.lineSeparator());
	}

	@Override
	public synchronized void receiveResponse(Response response) {
		buffer.append(System.lineSeparator()).append("<-----   ");
		appendResponseDetails(response);
	}

	@Override
	public synchronized void receiveEmptyMessage(final EmptyMessage message) {
		buffer.append(System.lineSeparator()).append("<-----   ");
		appendEmptyMessageDetails(message);
	}
}
