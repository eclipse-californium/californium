/*******************************************************************************
 * Copyright (c) 2018 Sierra Wireless and others.
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
 *    Sierra Wireless - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.test;

import java.util.concurrent.atomic.AtomicBoolean;

import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.interceptors.MessageInterceptorAdapter;
import org.eclipse.californium.elements.EndpointContext;
import org.eclipse.californium.elements.util.IntendedTestException;

public class ErrorInjector extends MessageInterceptorAdapter {

	private AtomicBoolean errorOnEstablishedContext = new AtomicBoolean(false);
	private AtomicBoolean errorOnSent = new AtomicBoolean(false);
	private AtomicBoolean errorOnReadyToSend = new AtomicBoolean(false);

	public void setErrorOnEstablishedContext() {
		errorOnEstablishedContext.set(true);
	}

	public void setErrorOnSent() {
		errorOnSent.set(true);
	}

	public void setErrorOnReadyToSend() {
		errorOnReadyToSend.set(true);
	}

	@Override
	public void sendRequest(final Request request) {
		request.addMessageObserver(new ErrorInjectorMessageObserver());
	}

	@Override
	public void sendResponse(final Response response) {
		response.addMessageObserver(new ErrorInjectorMessageObserver());
	}

	public class ErrorInjectorMessageObserver extends MessageObserverAdapter {

		@Override
		public void onReadyToSend() {
			if (errorOnReadyToSend.compareAndSet(true, false)) {
				throw new IntendedTestException("Simulate error before to sent");
			}
		}

		@Override
		public void onSent() {
			if (errorOnReadyToSend.compareAndSet(true, false)) {
				throw new IntendedTestException("Simulate error on sent");
			}
		}

		@Override
		public void onContextEstablished(EndpointContext endpointContext) {
			if (errorOnEstablishedContext.compareAndSet(true, false)) {
				throw new IntendedTestException("Simulate error on context established");
			}
		}
	}
}
