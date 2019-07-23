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
 *    Bosch Software Innovations GmbH - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - implement DIRECT processing,
 *                                                    though NON multicast shown
 *                                                     to be too unreliable.
 ******************************************************************************/
package org.eclipse.californium.core.multicast;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

import java.net.InetSocketAddress;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.CountingCoapHandler;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Multicast unit test.
 *
 * Note: due to the nature of UDP, this test may fail sporadically, if native
 * sockets are used.
 */
@Category(Small.class)
public class MulticastTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.NATIVE, CoapNetworkRule.Mode.DIRECT);

	@ClassRule
	public static CoapThreadsRule cleanup = new CoapThreadsRule();

	private final static int TIMEOUT_MILLIS = 2000;
	private final static int PORT = CoAP.DEFAULT_COAP_PORT + 1000;

	private static NetworkConfig config;

	@BeforeClass
	public static void setupServer() {
		config = network.getStandardTestConfig();
		config.setInt(NetworkConfig.Keys.MULTICAST_BASE_MID, 20000);
		CoapServer server1 = new CoapServer(config);
		InetSocketAddress serverSocketAddress = new InetSocketAddress(PORT);
		Connector connector = new UdpMulticastConnector(serverSocketAddress, CoAP.MULTICAST_IPV4);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		builder.setConnector(connector);
		server1.addEndpoint(builder.build());
		server1.add(new CoapResource("hello") {

			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.respond(ResponseCode.CONTENT, "Hello World 1!");
			}
		});
		server1.add(new CoapResource("no") {

			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.reject();
			}
		});
		server1.start();
		cleanup.add(server1);

		CoapServer server2 = new CoapServer();
		connector = new UdpMulticastConnector(serverSocketAddress, CoAP.MULTICAST_IPV4);
		builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		builder.setConnector(connector);
		server2.addEndpoint(builder.build());
		server2.add(new CoapResource("hello") {

			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.respond(ResponseCode.CONTENT, "Hello World 2!");
			}
		});
		server2.add(new CoapResource("no") {

			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.respond(ResponseCode.CONTENT, "no!");
			}
		});
		server2.start();
		cleanup.add(server2);
	}

	@Test
	public void clientMulticastCheckResponseText() {
		CountingCoapHandler handler = new CountingCoapHandler();
		Request request = Request.newGet();
		request.setURI("coap://" + CoAP.MULTICAST_IPV4.getHostAddress() + ":" + PORT + "/hello");
		request.setType(Type.NON);
		CoapClient client = new CoapClient();
		cleanup.add(client);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		CoapEndpoint endpoint = builder.build();
		cleanup.add(endpoint);
		client.setEndpoint(endpoint);
		client.advanced(handler, request);
		CoapResponse response = handler.waitOnLoad(TIMEOUT_MILLIS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getResponseText(), anyOf(is("Hello World 1!"), is("Hello World 2!")));
		response = handler.waitOnLoad(TIMEOUT_MILLIS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getResponseText(), anyOf(is("Hello World 1!"), is("Hello World 2!")));
	}

	@Test
	public void clientMulticastCheckReject() {
		CountingCoapHandler handler = new CountingCoapHandler();
		Request request = Request.newGet();
		request.setURI("coap://" + CoAP.MULTICAST_IPV4.getHostAddress() + ":" + PORT + "/no");
		request.setType(Type.NON);
		CoapClient client = new CoapClient();
		cleanup.add(client);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		CoapEndpoint endpoint = builder.build();
		cleanup.add(endpoint);
		client.setEndpoint(endpoint);
		client.advanced(handler, request);
		CoapResponse response = handler.waitOnLoad(TIMEOUT_MILLIS);
		assertThat(response, is(notNullValue()));
		assertThat(response.getResponseText(), is("no!"));

		response = handler.waitOnLoad(TIMEOUT_MILLIS);
		assertThat(response, is(nullValue()));
		assertThat(request.isRejected(), is(false));
	}
}
