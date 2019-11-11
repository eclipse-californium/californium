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
 ******************************************************************************/
package org.eclipse.californium.core.test.lockstep;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.elements.util.IntendedTestException;

/**
 * A message interceptor for tracing messages from the viewpoint of a CoAP
 * client.
 *
 */
public final class ClientBlockwiseInterceptor extends BlockwiseInterceptor implements MessageInterceptor {

	@Override
	public synchronized void sendRequest(final Request request) {
		logNewLine();
		appendRequestDetails(request);
		if (errorInjector != null) {
			buffer.append("    (should be dropped by error)");
			TestTools.removeMessageObservers(request, LoggingMessageObserver.class);
			request.addMessageObserver(new LoggingMessageObserver(errorInjector) {

				@Override
				public void log(IntendedTestException exception) {
					logNewLine();
					appendRequestDetails(request);
					if (exception == null) {
						buffer.append("    -----> (sent!)");
					} else {
						buffer.append("    -----> (dropped)");
					}
				};
			});
		}
		else {
			TestTools.removeMessageObservers(request, SendMessageObserver.class);
			request.addMessageObserver(new SendMessageObserver() {

				@Override
				public void log(String qualifier) {
					if (qualifier == null) {
						buffer.append("    ----->");
					} else {
						buffer.append("    -----> " + qualifier);
					}
				}
			});
		}
	}

	@Override
	public synchronized void sendResponse(final Response response) {
		logNewLine();
		buffer.append("ERROR: Server received ").append(response);
	}

	@Override
	public synchronized void sendEmptyMessage(final EmptyMessage message) {
		logNewLine();
		appendEmptyMessageDetails(message);
		buffer.append("   ----->");
	}

	@Override
	public synchronized void receiveRequest(final Request request) {
		logNewLine();
		buffer.append("ERROR: Server sent ").append(request);
	}

	@Override
	public synchronized void receiveResponse(Response response) {
		logNewLine("<-----   ");
		appendResponseDetails(response);
	}

	@Override
	public synchronized void receiveEmptyMessage(final EmptyMessage message) {
		logNewLine("<-----   ");
		appendEmptyMessageDetails(message);
	}
}
