/*******************************************************************************
 * Copyright (c) 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 */
package org.eclipse.californium.core.network.stack;

import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.MessageObserverAdapter;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;

/**
 * Handle response timeout for request. It Should mark request as timeout if responseTimeout expired.
 * 
 * @see Request#getResponseTimeout()
 */
public class ResponseTimeoutLayer extends AbstractLayer {
	
	@Override
	public void sendRequest(final Exchange exchange,final Request request) {
		if (request.getResponseTimeout() > 0) {
			
			// Schedule task at timeout
			final ScheduledFuture<?> task = executor.schedule(new Runnable() {
				@Override
				public void run() {
					exchange.setTimedOut(request);
				}
			}, request.getResponseTimeout(), TimeUnit.MILLISECONDS);

			// Cancel task if response received or request failed before.
			request.addMessageObserver(new MessageObserverAdapter() {

				@Override
				public void onResponse(Response response) {
					task.cancel(false);
				}
				
				@Override
				protected void failed() {
					task.cancel(false);
				}
			});
		}
		
		lower().sendRequest(exchange, request);
	}
}
