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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.TcpEndpointContextMatcher;
import org.eclipse.californium.elements.UdpEndpointContextMatcher;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.config.SystemConfig;
import org.eclipse.californium.elements.config.TcpConfig;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.TestSynchroneExecutor;
import org.eclipse.californium.elements.util.TestThreadFactory;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.ArgumentCaptor;

@Category(Small.class) @RunWith(Parameterized.class)
public class CoapStackTest {

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	private final CoapStack stack;
	private final Outbox outbox;

	public CoapStackTest(CoapStack stack, Outbox outbox) {
		this.stack = stack;
		ScheduledExecutorService executor = ExecutorsUtil.newSingleThreadScheduledExecutor(new TestThreadFactory("coap-stack-"));
		cleanup.add(executor);
		this.stack.setExecutors(executor, executor);
		this.outbox = outbox;
	}

	@Parameterized.Parameters public static List<Object[]> parameters() {
		Outbox udpOutbox = mock(Outbox.class);
		Outbox tcpOutbox = mock(Outbox.class);

		SystemConfig.register();
		TcpConfig.register();
		CoapConfig.register();
		Configuration config = Configuration.createStandardWithoutFile();

		List<Object[]> parameters = new ArrayList<>();
		parameters.add(new Object[]{new CoapTcpStack("tcp-test ", config, new TcpEndpointContextMatcher(), tcpOutbox), tcpOutbox});
		parameters.add(new Object[]{new CoapUdpStack("udp-test ", config, new UdpEndpointContextMatcher(true), udpOutbox), udpOutbox});
		return parameters;
	}

	@Test public void cancelledMessageExpectExchangeComplete() {
		final Request request = new Request(CoAP.Code.GET);
		request.setDestinationContext(new AddressEndpointContext(InetAddress.getLoopbackAddress(), CoAP.DEFAULT_COAP_PORT));
		final Exchange exchange = new Exchange(request, request.getDestinationContext().getPeerAddress(), Origin.LOCAL, TestSynchroneExecutor.TEST_EXECUTOR);
		ArgumentCaptor<Exchange> exchangeCaptor = ArgumentCaptor.forClass(Exchange.class);
		doNothing().when(outbox).sendRequest(exchangeCaptor.capture(), eq(request));

		exchange.execute(new Runnable() {
			
			@Override
			public void run() {
				stack.sendRequest(exchange, request);
			}
		});

		// Capture exchange
		Exchange sendExchange = exchangeCaptor.getValue();
		assertFalse(sendExchange.isComplete());

		request.setCanceled(true);
		assertTrue(sendExchange.isComplete());
	}
}
