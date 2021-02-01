/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations GmbH - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - implement DIRECT processing,
 *                                                    though NON multicast shown
 *                                                    to be too unreliable.
 ******************************************************************************/
package org.eclipse.californium.core.multicast;

import static org.hamcrest.CoreMatchers.anyOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.Utils;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.interceptors.HealthStatisticLogger;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.core.test.CountingCoapHandler;
import org.eclipse.californium.elements.UDPConnector;
import org.eclipse.californium.elements.UdpMulticastConnector;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.NetworkInterfacesUtil;
import org.eclipse.californium.elements.util.StringUtil;
import org.eclipse.californium.elements.util.TestConditionTools;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.hamcrest.Matcher;
import org.junit.After;
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
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.NATIVE,
			CoapNetworkRule.Mode.DIRECT);

	@ClassRule
	public static CoapThreadsRule cleanup = new CoapThreadsRule();

	private final static long TIMEOUT_MILLIS = 2000;
	private final static int PORT = CoAP.DEFAULT_COAP_PORT + 1000;
	private final static int PORT2 = PORT + 1000;

	private static final InetAddress MULTICAST_IPV4_2 = new InetSocketAddress("224.0.1.189", 0).getAddress();

	private static NetworkConfig config;
	private static InetSocketAddress unicast;
	private static HealthStatisticLogger health = new HealthStatisticLogger("client", true);

	@BeforeClass
	public static void setupServer() {
		config = network.getStandardTestConfig();
		config.setInt(NetworkConfig.Keys.MULTICAST_BASE_MID, 20000);

		CoapServer server1 = new CoapServer(config);
		InetAddress host = NetworkInterfacesUtil.getMulticastInterfaceIpv4();
		if (host == null) {
			host = InetAddress.getLoopbackAddress();
		}

		UdpMulticastConnector.Builder multicastBuilder = new UdpMulticastConnector.Builder();
		multicastBuilder.setLocalPort(PORT).addMulticastGroup(CoAP.MULTICAST_IPV4);
		UDPConnector connector = multicastBuilder.build();

		CoapEndpoint.Builder coapBuilder = new CoapEndpoint.Builder();
		coapBuilder.setNetworkConfig(config);
		coapBuilder.setConnector(connector);
		server1.addEndpoint(coapBuilder.build());

		multicastBuilder = new UdpMulticastConnector.Builder();
		multicastBuilder.setLocalPort(PORT).addMulticastGroup(MULTICAST_IPV4_2);
		connector = multicastBuilder.build();

		coapBuilder = new CoapEndpoint.Builder();
		coapBuilder.setNetworkConfig(config);
		coapBuilder.setConnector(connector);
		server1.addEndpoint(coapBuilder.build());
		server1.add(new CoapResource("hello") {

			@Override
			public void handleGET(CoapExchange exchange) {
				InetSocketAddress localAddress = exchange.advanced().getRequest().getLocalAddress();
				String receiver = StringUtil.toString(localAddress.getAddress());
				exchange.respond(ResponseCode.CONTENT, "Hello Multicast-World 1! " + receiver);
				System.out.println("server 1 response");
			}
		});
		server1.add(new CoapResource("no") {

			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.reject();
				if (exchange.isMulticastRequest()) {
					System.out.println("server 1 mc reject");
				} else {
					System.out.println("server 1 reject");
				}
			}
		});
		server1.start();
		cleanup.add(server1);

		CoapServer server2 = new CoapServer();
		multicastBuilder = new UdpMulticastConnector.Builder();
		multicastBuilder.setLocalPort(PORT).addMulticastGroup(CoAP.MULTICAST_IPV4);
		connector = multicastBuilder.build();

		coapBuilder = new CoapEndpoint.Builder();
		coapBuilder.setNetworkConfig(config);
		coapBuilder.setConnector(connector);
		server2.addEndpoint(coapBuilder.build());
		server2.add(new CoapResource("hello") {

			@Override
			public void handleGET(CoapExchange exchange) {
				InetSocketAddress localAddress = exchange.advanced().getRequest().getLocalAddress();
				String receiver = StringUtil.toString(localAddress.getAddress());
				exchange.respond(ResponseCode.CONTENT, "Hello Multicast-World 2! " + receiver);
				System.out.println("server 2 response");
			}
		});
		server2.add(new CoapResource("no") {

			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.respond(ResponseCode.CONTENT, "no!");
				System.out.println("server 2 no");
			}
		});
		server2.start();
		cleanup.add(server2);

		unicast = new InetSocketAddress(host, PORT);
		CoapServer server3 = new CoapServer(config);
		connector = new UDPConnector(unicast);
		connector.setReuseAddress(true);
		coapBuilder = new CoapEndpoint.Builder();
		coapBuilder.setNetworkConfig(config);
		coapBuilder.setConnector(connector);
		CoapEndpoint coapEndpoint = coapBuilder.build();

		multicastBuilder = new UdpMulticastConnector.Builder();
		multicastBuilder.setLocalPort(PORT).addMulticastGroup(CoAP.MULTICAST_IPV4).setMulticastReceiver(true);
		connector.addMulticastReceiver(multicastBuilder.build());
		multicastBuilder = new UdpMulticastConnector.Builder();
		multicastBuilder.setLocalPort(PORT2).addMulticastGroup(CoAP.MULTICAST_IPV4).setMulticastReceiver(true);
		connector.addMulticastReceiver(multicastBuilder.build());
		server3.addEndpoint(coapEndpoint);

		server3.add(new CoapResource("hello") {

			@Override
			public void handleGET(CoapExchange exchange) {
				InetSocketAddress localAddress = exchange.advanced().getRequest().getLocalAddress();
				String receiver = StringUtil.toString(localAddress.getAddress());
				if (exchange.isMulticastRequest()) {
					exchange.respond(ResponseCode.CONTENT, "Hello Multicast-Unicast-World! " + receiver);
					System.out.println("server 3 mc-response");
				} else {
					exchange.respond(ResponseCode.CONTENT, "Hello Unicast-World! " + receiver);
					System.out.println("server 3 response");
				}
			}
		});
		server3.add(new CoapResource("no") {

			@Override
			public void handleGET(CoapExchange exchange) {
				exchange.reject();
				if (exchange.isMulticastRequest()) {
					System.out.println("server 3 mc reject");
				} else {
					System.out.println("server 3 reject");
				}
			}
		});
		server3.start();
		cleanup.add(server3);
	}

	@After
	public void cleanup() {
		health.reset();
	}

	@Test
	public void clientMulticastCheckResponseText() throws InterruptedException {
		String uri = "coap://" + CoAP.MULTICAST_IPV4.getHostAddress() + ":" + PORT + "/hello";
		String receiver = StringUtil.toString(CoAP.MULTICAST_IPV4);
		CountingCoapHandler handler = new CountingCoapHandler();
		Request request = Request.newGet();
		request.setURI(uri);
		request.setType(Type.NON);
		System.out.println("Multicast: " + uri);
		System.out.println(Utils.prettyPrint(request));
		CoapClient client = new CoapClient();
		cleanup.add(client);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		CoapEndpoint endpoint = builder.build();
		cleanup.add(endpoint);
		endpoint.addPostProcessInterceptor(health);
		client.setEndpoint(endpoint);
		client.advanced(handler, request);
		CoapResponse response = handler.waitOnLoad(TIMEOUT_MILLIS);
		assertThat("missing 1. response", response, is(notNullValue()));
		assertThat(response.getResponseText(), anyOf(is("Hello Multicast-World 1! 0.0.0.0"),
				is("Hello Multicast-World 2! 0.0.0.0"), is("Hello Multicast-Unicast-World! " + receiver)));
		response = handler.waitOnLoad(TIMEOUT_MILLIS);
		assertThat("missing 2. response", response, is(notNullValue()));
		assertThat(response.getResponseText(), anyOf(is("Hello Multicast-World 1! 0.0.0.0"),
				is("Hello Multicast-World 2! 0.0.0.0"), is("Hello Multicast-Unicast-World! " + receiver)));
		assertThat("missing 3. response", response, is(notNullValue()));
		assertThat(response.getResponseText(), anyOf(is("Hello Multicast-World 1! 0.0.0.0"),
				is("Hello Multicast-World 2! 0.0.0.0"), is("Hello Multicast-Unicast-World! " + receiver)));
		assertHealthCounter("send-requests", is(1L), TIMEOUT_MILLIS);
		assertHealthCounter("send-rejects", is(0L));
		assertHealthCounter("send-request retransmissions", is(0L));
		assertHealthCounter("recv-responses", is(3L), TIMEOUT_MILLIS);
		assertHealthCounter("recv-duplicate responses", is(0L));
		assertHealthCounter("recv-acks", is(0L));
		assertHealthCounter("recv-rejects", is(0L));
	}

	@Test
	public void clientAltMulticastCheckResponseText() throws InterruptedException {
		String uri = "coap://" + MULTICAST_IPV4_2.getHostAddress() + ":" + PORT + "/hello";
		CountingCoapHandler handler = new CountingCoapHandler();
		Request request = Request.newGet();
		request.setURI(uri);
		request.setType(Type.NON);
		System.out.println("Multicast: " + uri);
		System.out.println(Utils.prettyPrint(request));
		CoapClient client = new CoapClient();
		cleanup.add(client);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		CoapEndpoint endpoint = builder.build();
		cleanup.add(endpoint);
		endpoint.addPostProcessInterceptor(health);
		client.setEndpoint(endpoint);
		client.advanced(handler, request);
		CoapResponse response = handler.waitOnLoad(TIMEOUT_MILLIS);
		assertThat("missing response", response, is(notNullValue()));
		assertThat(response.getResponseText(), is("Hello Multicast-World 1! 0.0.0.0"));
		response = handler.waitOnLoad(TIMEOUT_MILLIS);
		assertThat(response, is(nullValue()));
		assertHealthCounter("send-requests", is(1L), TIMEOUT_MILLIS);
		assertHealthCounter("send-rejects", is(0L));
		assertHealthCounter("send-request retransmissions", is(0L));
		assertHealthCounter("recv-responses", is(1L), TIMEOUT_MILLIS);
		assertHealthCounter("recv-duplicate responses", is(0L));
		assertHealthCounter("recv-acks", is(0L));
		assertHealthCounter("recv-rejects", is(0L));
	}

	@Test
	public void clientMulticastChangePort() throws InterruptedException {
		String uri = "coap://" + CoAP.MULTICAST_IPV4.getHostAddress() + ":" + PORT2 + "/hello";
		String receiver = StringUtil.toString(CoAP.MULTICAST_IPV4);
		CountingCoapHandler handler = new CountingCoapHandler();
		Request request = Request.newGet();
		request.setURI(uri);
		request.setType(Type.NON);
		System.out.println("Multicast: " + uri);
		System.out.println(Utils.prettyPrint(request));
		CoapClient client = new CoapClient();
		cleanup.add(client);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		CoapEndpoint endpoint = builder.build();
		cleanup.add(endpoint);
		endpoint.addPostProcessInterceptor(health);
		client.setEndpoint(endpoint);
		client.advanced(handler, request);
		CoapResponse response = handler.waitOnLoad(TIMEOUT_MILLIS);
		assertThat("missing response", response, is(notNullValue()));
		assertThat(response.getResponseText(), is("Hello Multicast-Unicast-World! " + receiver));
		assertHealthCounter("send-requests", is(1L), TIMEOUT_MILLIS);
		assertHealthCounter("send-rejects", is(0L));
		assertHealthCounter("send-request retransmissions", is(0L));
		assertHealthCounter("recv-responses", is(1L), TIMEOUT_MILLIS);
		assertHealthCounter("recv-duplicate responses", is(0L));
		assertHealthCounter("recv-acks", is(0L));
		assertHealthCounter("recv-rejects", is(0L));
	}

	@Test
	public void clientUnicast() throws InterruptedException {
		String uri = "coap://" + StringUtil.toString(unicast) + "/hello";
		String receiver = StringUtil.toString(unicast.getAddress());
		CoapClient client = new CoapClient();
		cleanup.add(client);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		CoapEndpoint endpoint = builder.build();
		cleanup.add(endpoint);
		endpoint.addPostProcessInterceptor(health);
		client.setEndpoint(endpoint);
		CountingCoapHandler handler = new CountingCoapHandler();
		Request request = Request.newGet();
		request.setURI(uri);
		request.setType(Type.NON);
		System.out.println("Unicast: " + uri);
		System.out.println(Utils.prettyPrint(request));
		client.advanced(handler, request);
		CoapResponse response = handler.waitOnLoad(TIMEOUT_MILLIS);
		assertThat(response, is(notNullValue()));
		System.out.println(response.getResponseText());
		assertThat(response.getResponseText(), is("Hello Unicast-World! " + receiver));
		assertHealthCounter("send-requests", is(1L), TIMEOUT_MILLIS);
		assertHealthCounter("send-rejects", is(0L));
		assertHealthCounter("send-request retransmissions", is(0L));
		assertHealthCounter("recv-responses", is(1L), TIMEOUT_MILLIS);
		assertHealthCounter("recv-duplicate responses", is(0L));
		assertHealthCounter("recv-acks", is(0L));
		assertHealthCounter("recv-rejects", is(0L));
		assertHealthCounter("recv-ignored", is(0L));
	}

	@Test
	public void clientUnicastReject() throws InterruptedException {
		String uri = "coap://" + StringUtil.toString(unicast) + "/no";
		CoapClient client = new CoapClient();
		cleanup.add(client);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		CoapEndpoint endpoint = builder.build();
		cleanup.add(endpoint);
		endpoint.addPostProcessInterceptor(health);
		client.setEndpoint(endpoint);
		CountingCoapHandler handler = new CountingCoapHandler();
		Request request = Request.newGet();
		request.setURI(uri);
		request.setType(Type.NON);
		System.out.println("Unicast: " + uri);
		System.out.println(Utils.prettyPrint(request));
		client.advanced(handler, request);
		CoapResponse response = handler.waitOnLoad(TIMEOUT_MILLIS);
		assertThat(response, is(nullValue()));
		assertThat(request.isRejected(), is(true));
		assertHealthCounter("send-requests", is(1L), TIMEOUT_MILLIS);
		assertHealthCounter("send-rejects", is(0L));
		assertHealthCounter("send-request retransmissions", is(0L));
		assertHealthCounter("recv-responses", is(0L));
		assertHealthCounter("recv-duplicate responses", is(0L));
		assertHealthCounter("recv-acks", is(0L));
		assertHealthCounter("recv-rejects", is(1L), TIMEOUT_MILLIS);
		assertHealthCounter("recv-ignored", is(0L));
	}

	@Test
	public void clientMulticastCheckReject() throws InterruptedException {
		String uri = "coap://" + CoAP.MULTICAST_IPV4.getHostAddress() + ":" + PORT + "/no";
		CountingCoapHandler handler = new CountingCoapHandler();
		Request request = Request.newGet();
		request.setURI(uri);
		request.setType(Type.NON);
		System.out.println("Multicast: " + uri);
		System.out.println(Utils.prettyPrint(request));
		CoapClient client = new CoapClient();
		cleanup.add(client);
		CoapEndpoint.Builder builder = new CoapEndpoint.Builder();
		builder.setNetworkConfig(config);
		CoapEndpoint endpoint = builder.build();
		cleanup.add(endpoint);
		endpoint.addPostProcessInterceptor(health);
		client.setEndpoint(endpoint);
		client.advanced(handler, request);
		CoapResponse response = handler.waitOnLoad(TIMEOUT_MILLIS);
		assertThat("missing response", response, is(notNullValue()));
		assertThat(response.getResponseText(), is("no!"));

		response = handler.waitOnLoad(TIMEOUT_MILLIS);
		assertThat("unexpected response", response, is(nullValue()));
		assertThat(request.isRejected(), is(false));

		assertHealthCounter("send-requests", is(1L), TIMEOUT_MILLIS);
		assertHealthCounter("send-rejects", is(0L));
		assertHealthCounter("send-request retransmissions", is(0L));
		assertHealthCounter("recv-responses", is(1L), TIMEOUT_MILLIS);
		assertHealthCounter("recv-duplicate responses", is(0L));
		assertHealthCounter("recv-acks", is(0L));
		// multicast reject are ignored
		assertHealthCounter("recv-rejects", is(0L));
		// server 3 blocks sending rejects
		assertHealthCounter("recv-ignored", is(1L), TIMEOUT_MILLIS);
	}

	private void assertHealthCounter(final String name, final Matcher<? super Long> matcher, long timeout)
			throws InterruptedException {
		TestConditionTools.assertStatisticCounter(health, name, matcher, timeout, TimeUnit.MILLISECONDS);
	}

	private void assertHealthCounter(String name, Matcher<? super Long> matcher) {
		TestConditionTools.assertStatisticCounter(health, name, matcher);
	}
}
