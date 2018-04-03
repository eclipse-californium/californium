/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH               - initial creation
 *                                                    moved from ResourceAttributesTest
 ******************************************************************************/
package org.eclipse.californium.core;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointObserver;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.server.MessageDeliverer;

public class DummyEndpoint implements Endpoint {

	@Override
	public void start() throws IOException {
	}

	@Override
	public void stop() {
	}

	@Override
	public void destroy() {
	}

	@Override
	public void clear() {
	}

	@Override
	public boolean isStarted() {
		return false;
	}

	@Override
	public void setExecutor(ScheduledExecutorService executor) {
	}

	@Override
	public void addObserver(EndpointObserver obs) {
	}

	@Override
	public void removeObserver(EndpointObserver obs) {
	}

	@Override
	public void addNotificationListener(NotificationListener lis) {
	}

	@Override
	public void removeNotificationListener(NotificationListener lis) {
	}

	@Override
	public void addInterceptor(MessageInterceptor interceptor) {
	}

	@Override
	public void removeInterceptor(MessageInterceptor interceptor) {
	}

	@Override
	public List<MessageInterceptor> getInterceptors() {
		return null;
	}

	@Override
	public void sendRequest(Request request) {
	}

	@Override
	public void sendResponse(Exchange exchange, Response response) {
		exchange.setResponse(response);
	}

	@Override
	public void sendEmptyMessage(Exchange exchange, EmptyMessage message) {
	}

	@Override
	public void setMessageDeliverer(MessageDeliverer deliverer) {
	}

	@Override
	public InetSocketAddress getAddress() {
		return null;
	}

	@Override
	public URI getUri() {
		return null;
	}

	@Override
	public NetworkConfig getConfig() {
		return null;
	}

	@Override
	public void cancelObservation(Token token) {
	}
	
}