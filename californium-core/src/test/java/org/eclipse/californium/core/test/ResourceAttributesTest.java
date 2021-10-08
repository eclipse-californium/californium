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
 *    Achim Kraus (Bosch Software Innovations GmbH) - test limited search to 1 query.
 ******************************************************************************/
package org.eclipse.californium.core.test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;

import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.EmptyMessage;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.Token;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.EndpointObserver;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.interceptors.MessageInterceptor;
import org.eclipse.californium.core.observe.NotificationListener;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.core.server.resources.DiscoveryResource;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestNameLoggerRule;
import org.eclipse.californium.elements.util.TestSynchroneExecutor;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Category(Small.class)
public class ResourceAttributesTest {
	private static final Logger LOGGER = LoggerFactory.getLogger(ResourceAttributesTest.class);

	@Rule
	public TestNameLoggerRule name = new TestNameLoggerRule();

	private Resource root;

	@Before
	public void setup() {
		try {
			root = new CoapResource("");
			Resource sensors = new CoapResource("sensors");
			Resource temp = new CoapResource("temp");
			Resource light = new CoapResource("light");
			root.add(sensors);
			sensors.add(temp);
			sensors.add(light);

			sensors.getAttributes().setTitle("Sensor Index");
			temp.getAttributes().addResourceType("temperature-c");
			temp.getAttributes().addInterfaceDescription("sensor");
			temp.getAttributes().addAttribute("foo");
			temp.getAttributes().addAttribute("bar", "one");
			temp.getAttributes().addAttribute("bar", "two");
			light.getAttributes().addResourceType("light-lux");
			light.getAttributes().addInterfaceDescription("sensor");
		} catch (Throwable t) {
			t.printStackTrace();
		}
	}

	@Test
	public void testDiscovery() {

		final String expectedTree = new StringBuilder()
				.append("</sensors>;title=\"Sensor Index\",")
				.append("</sensors/light>;if=\"sensor\";rt=\"light-lux\",")
				.append("</sensors/temp>;bar=\"one two\";foo;if=\"sensor\";rt=\"temperature-c\"")
				.toString();
		DiscoveryResource discovery = new DiscoveryResource(root);
		String serialized = discovery.discoverTree(root, new LinkedList<String>());
		LOGGER.info(serialized);
		Assert.assertEquals(expectedTree, serialized);
	}

	@Test
	public void testDiscoveryFiltering() {

		final String expectedTree = "</sensors/light>;if=\"sensor\";rt=\"light-lux\"";
		Request request = Request.newGet();
		request.setURI("coap://localhost/.well-known/core?rt=light-lux");

		DiscoveryResource discovery = new DiscoveryResource(root);
		String serialized = discovery.discoverTree(root, request.getOptions().getUriQuery());
		LOGGER.info(serialized);
		Assert.assertEquals(expectedTree, serialized);
	}

	@Test
	public void testDiscoveryMultiFiltering() {
		Request request = Request.newGet();
		request.setURI("coap://localhost/.well-known/core?rt=light-lux&rt=temprature-cel");

		final Exchange exchange = new Exchange(request, request.getDestinationContext().getPeerAddress(), Origin.REMOTE, TestSynchroneExecutor.TEST_EXECUTOR);
		exchange.setEndpoint(new DummyEndpoint());
		exchange.execute(new Runnable() {

			@Override
			public void run() {
				DiscoveryResource discovery = new DiscoveryResource(root);

				discovery.handleRequest(exchange);
			}
		});

		LOGGER.info(exchange.getResponse().getPayloadString());
		Assert.assertEquals(ResponseCode.BAD_OPTION, exchange.getResponse().getCode());
	}

	private static class DummyEndpoint implements Endpoint {

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
		public void setExecutors(ScheduledExecutorService executor, ScheduledExecutorService secondaryExecutor) {
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
		public Configuration getConfig() {
			return null;
		}

		@Override
		public void cancelObservation(Token token) {
		}

		@Override
		public void addPostProcessInterceptor(MessageInterceptor interceptor) {
		}

		@Override
		public void removePostProcessInterceptor(MessageInterceptor interceptor) {
		}

		@Override
		public List<MessageInterceptor> getPostProcessInterceptors() {
			return null;
		}

	}
}
