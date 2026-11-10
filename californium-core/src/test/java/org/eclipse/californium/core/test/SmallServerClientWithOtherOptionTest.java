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
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 *    Achim Kraus (Bosch Software Innovations GmbH) - destroy server after test
 *    Rogier Cobben - created other option test based on SmallServerClientTest.
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.net.InetSocketAddress;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.option.MapBasedOptionRegistry;
import org.eclipse.californium.core.coap.option.StandardOptionRegistry;
import org.eclipse.californium.core.coap.option.StringOption;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.interceptors.MessageTracer;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.category.Medium;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This is a small test that tests the exchange of one request and one response with other option.
 */
@Category(Medium.class)
public class SmallServerClientWithOtherOptionTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(SmallServerClientWithOtherOptionTest.class);

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	private static String SERVER_RESPONSE = "server responds hi";

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	private InetSocketAddress serverAddress;
	
	private static StringOption.Definition OPTION_65008= new StringOption.Definition(65008, "option-65008", false, 0, 200);

	@Before
	public void init() {
		EndpointManager.getEndpointManager().setDefaultEndpoint(createClientEndpoint());
		cleanup.add(createSimpleServer());
	}

	@Test
	public void testNonconfirmable() throws Exception {

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
	
	private CoapEndpoint createClientEndpoint() {
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		CoapEndpoint endpoint = builder.build();
		endpoint.addInterceptor( new MessageTracer() );
		return endpoint;
	}

	private MapBasedOptionRegistry createEndpointOptionRegistry() {
		return new MapBasedOptionRegistry(StandardOptionRegistry.getDefaultOptionRegistry(), OPTION_65008);
	}

	private CoapServer createSimpleServer() {
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setInetSocketAddress(TestTools.LOCALHOST_EPHEMERAL);
		builder.setOptionRegistry(createEndpointOptionRegistry() );
		CoapEndpoint endpoint = builder.build();
		endpoint.addInterceptor( new MessageTracer() );
		CoapServer server = new CoapServer(network.getStandardTestConfig());
		server.addEndpoint(endpoint);
		server.setMessageDeliverer(new MessageDeliverer() {
			@Override
			public void deliverRequest(Exchange exchange) {
				LOGGER.info("server received request");
				exchange.sendAccept();
				try { 
					Thread.sleep(500);
				} catch (InterruptedException e) {
				}
				Response response = new Response(ResponseCode.CONTENT);
				response.setConfirmable(false);
				response.getOptions().addOption(OPTION_65008.create(""));
				response.getOptions().addOption(OPTION_65008.create("value of the other option"));
				response.setPayload(SERVER_RESPONSE);
				exchange.sendResponse(response);
			}
			@Override
			public void deliverResponse(Exchange exchange, Response response) { }
		});
		server.start();
		serverAddress = endpoint.getAddress();
		return server;
	}
}
