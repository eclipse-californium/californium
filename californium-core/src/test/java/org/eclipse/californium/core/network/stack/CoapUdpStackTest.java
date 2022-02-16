/*******************************************************************************
 * Copyright (c) 2016, 2017 Amazon Web Services and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v2.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v20.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 * Joe Magerramov (Amazon Web Services) - CoAP over TCP support.
 * others - refer to gitlog
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

import java.net.InetAddress;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.UdpEndpointContextMatcher;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.TestSynchroneExecutor;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

@Category(Small.class) @RunWith(MockitoJUnitRunner.class)
public class CoapUdpStackTest {

	private static final Configuration CONFIG = Configuration.createStandardWithoutFile();

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Mock private Outbox outbox;
	@Mock private MessageDeliverer deliverer;
	@Mock private ScheduledExecutorService executor;

	private CoapStack stack;

	@Before
	public void initialize() {
		stack = new CoapUdpStack("udp-test ", CONFIG, new UdpEndpointContextMatcher(true), outbox);
		stack.setDeliverer(deliverer);
		stack.setExecutors(executor, executor);

	}

	@Test public void sendEmptyMessageExpectSent() {
		EmptyMessage message = new EmptyMessage(CoAP.Type.RST);
		stack.sendEmptyMessage(null, message);

		verify(outbox).sendEmptyMessage(null, message);
	}

	@Test public void sendRequestExpectSent() {
		final Request request = new Request(CoAP.Code.GET);
		request.setDestinationContext(new AddressEndpointContext(InetAddress.getLoopbackAddress(), CoAP.DEFAULT_COAP_PORT));
		final Exchange exchange = new Exchange(request, request.getDestinationContext().getPeerAddress(), Origin.LOCAL, TestSynchroneExecutor.TEST_EXECUTOR);
		exchange.execute(new Runnable() {
			
			@Override
			public void run() {
				stack.sendRequest(exchange, request);
			}
		});

		verify(outbox).sendRequest(any(Exchange.class), eq(request));
	}


	@Test public void sendResponseExpectSent() {
		Request request = new Request(CoAP.Code.GET);
		request.setSourceContext(new AddressEndpointContext(InetAddress.getLoopbackAddress(), CoAP.DEFAULT_COAP_PORT));
		final Exchange exchange = new Exchange(request, request.getSourceContext().getPeerAddress(), Origin.REMOTE, TestSynchroneExecutor.TEST_EXECUTOR);
		final Response response = new Response(CoAP.ResponseCode.CONTENT);
		exchange.execute(new Runnable() {
			@Override
			public void run() {
				stack.sendResponse(exchange, response);
			}
		});

		verify(outbox).sendResponse(exchange, response);
	}
}
