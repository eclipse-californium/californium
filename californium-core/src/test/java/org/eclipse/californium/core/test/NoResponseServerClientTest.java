/*******************************************************************************
 * Copyright (c) 2021 Bosch.IO GmbH and others.
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
 *    Bosch IO.GmbH - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.coap.NoResponseOption;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.test.MessageExchangeStoreTool.CoapTestEndpoint;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is a small test that tests the exchange of one request and one response.
 */
@Category(Medium.class)
public class NoResponseServerClientTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(NoResponseServerClientTest.class);

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	private static String SERVER_RESPONSE = "server responds hi";

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestTimeRule time = new TestTimeRule();

	private CoapTestEndpoint clientEndpoint;
	private CoapTestEndpoint serverEndpoint;
	private InetSocketAddress serverAddress;
	private Configuration config;

	@Before
	public void init() {
		config = network.createStandardTestConfig()
				.set(CoapConfig.EXCHANGE_LIFETIME, 10000, TimeUnit.MILLISECONDS)
				.set(CoapConfig.MARK_AND_SWEEP_INTERVAL, 1000, TimeUnit.MILLISECONDS)
				.set(CoapConfig.NON_LIFETIME, 1000, TimeUnit.MILLISECONDS)
				.set(CoapConfig.MAX_LATENCY, 1000, TimeUnit.MILLISECONDS)
				.set(CoapConfig.MAX_SERVER_RESPONSE_DELAY, 1000, TimeUnit.MILLISECONDS);
		cleanup.add(createSimpleServer());

		clientEndpoint = new CoapTestEndpoint(TestTools.LOCALHOST_EPHEMERAL, config);
		EndpointManager.getEndpointManager().setDefaultEndpoint(clientEndpoint);
	}

	@After
	public void shutdown() {
		MessageExchangeStoreTool.assertAllExchangesAreCompleted(serverEndpoint, time);
		MessageExchangeStoreTool.assertAllExchangesAreCompleted(clientEndpoint, time);
	}

	@Test
	public void testResponse() throws Exception {

		// send request
		Request request = new Request(CoAP.Code.POST);
		request.setConfirmable(false);
		request.setDestinationContext(new AddressEndpointContext(serverAddress));
		request.setPayload("client says hi");
		request.send();
		LOGGER.info("client sent request");

		// receive response and check
		Response response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		LOGGER.info("client received response");
		assertEquals(response.getPayloadString(), SERVER_RESPONSE);
	}

	@Test
	public void testNoResponse() throws Exception {

		// send request
		Request request = new Request(CoAP.Code.POST);
		request.setConfirmable(false);
		request.setDestinationContext(new AddressEndpointContext(serverAddress));
		request.setPayload("client says hi");
		request.getOptions().setNoResponse(NoResponseOption.SUPPRESS_SUCCESS);
		request.send();
		LOGGER.info("client sent request with no-response for success");

		// receive response and check
		Response response = request.waitForResponse(1000);
		assertNull("Client received unexpected response", response);
	}

	@Test
	public void testNoErrorResponse() throws Exception {

		// send request
		Request request = new Request(CoAP.Code.POST);
		request.setConfirmable(false);
		request.setDestinationContext(new AddressEndpointContext(serverAddress));
		request.setPayload("client says hi");
		request.getOptions().setNoResponse(NoResponseOption.SUPPRESS_CLIENT_ERROR);
		request.send();

		// receive response and check
		Response response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		LOGGER.info("client received response");
		assertEquals(response.getPayloadString(), SERVER_RESPONSE);
	}

	@Test
	public void testConNoResponse() throws Exception {

		// send request
		Request request = new Request(CoAP.Code.POST);
		request.setConfirmable(true);
		request.setDestinationContext(new AddressEndpointContext(serverAddress));
		request.setPayload("client says hi");
		request.getOptions().setNoResponse(NoResponseOption.SUPPRESS_SUCCESS);
		request.send();
		LOGGER.info("client sent request with no-response for success");

		// receive response and check
		Response response = request.waitForResponse(1000);
		assertNotNull("Client received no response", response);
		LOGGER.info("client received response");
		assertEquals(response.getPayloadString(), SERVER_RESPONSE);
	}

	@Test
	public void testConSeparateNoResponse() throws Exception {

		// send request
		Request request = new Request(CoAP.Code.POST);
		request.setConfirmable(true);
		request.setDestinationContext(new AddressEndpointContext(serverAddress));
		request.getOptions().setUriPath("ack");
		request.setPayload("client says hi");
		request.getOptions().setNoResponse(NoResponseOption.SUPPRESS_SUCCESS);
		request.send();
		LOGGER.info("client sent request with no-response for success");

		// receive response and check
		Response response = request.waitForResponse(1000);
		assertNull("Client received unexpected response", response);
	}

	private CoapServer createSimpleServer() {

		serverEndpoint = new CoapTestEndpoint(TestTools.LOCALHOST_EPHEMERAL, config);
		CoapServer server = new CoapServer(config);
		server.addEndpoint(serverEndpoint);
		server.setMessageDeliverer(new MessageDeliverer() {

			@Override
			public void deliverRequest(Exchange exchange) {
				String path = exchange.getRequest().getOptions().getUriPathString();
				LOGGER.info("server received request {}", path);
				if (path.equals("ack")) {
					exchange.sendAccept();
				}
				Response response = new Response(ResponseCode.CONTENT);
				response.setConfirmable(false);
				response.setPayload(SERVER_RESPONSE);
				exchange.sendResponse(response);
			}

			@Override
			public void deliverResponse(Exchange exchange, Response response) {
			}
		});
		server.start();
		serverAddress = serverEndpoint.getAddress();
		return server;
	}
}
