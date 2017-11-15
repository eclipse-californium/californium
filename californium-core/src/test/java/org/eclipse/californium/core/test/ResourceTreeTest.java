/*******************************************************************************
 * Copyright (c) 2015 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 ******************************************************************************/
package org.eclipse.californium.core.test;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Medium;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Medium.class)
public class ResourceTreeTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	public static final String RES_A = "A";
	public static final String RES_AA = "AA";
	
	public static final String NAME_1 = "first";
	public static final String NAME_2 = "second";
	public static final String PAYLOAD = "It is freezing";
	
	public static final String CHILD = "child";
	public static final String CHILD_PAYLOAD = "It is too cold";
	
	private CoapServer server;
	private int serverPort;
	
	private CoapResource resource;
	
	@Before
	public void startupServer() {
		System.out.println("\nStart "+getClass().getSimpleName());
		createServer();
	}
	
	@After
	public void shutdownServer() {
		server.destroy();
		EndpointManager.reset();
		System.out.println("End "+getClass().getSimpleName());
	}
	
	@Test
	public void testNameChange() throws Exception {
		String base = "coap://localhost:"+serverPort+"/"+RES_A+"/"+RES_AA+"/";
		
		// First check that we reach the resource
		String resp1 = Request.newGet().setURI(base+NAME_1).send().waitForResponse(1000).getPayloadString();
		Assert.assertEquals(PAYLOAD, resp1);
		
		// Check that the child of 'first' is also reachable
		String resp2 = Request.newGet().setURI(base+NAME_1+"/"+CHILD).send().waitForResponse(1000).getPayloadString();
		Assert.assertEquals(CHILD_PAYLOAD, resp2);
		
		// change the name to 'second'
		resource.setName(NAME_2);
		
		// Check that the resource reacts
		System.out.println("Check that the resource reacts");
		String resp3 = Request.newGet().setURI(base+NAME_2).send().waitForResponse(1000).getPayloadString();
		Assert.assertEquals(PAYLOAD, resp3);
		
		// Check that the child of (now) 'second' is also reachable
		System.out.println("Check that the child of (now) 'second' is also reachable");
		String resp4 = Request.newGet().setURI(base+NAME_2+"/"+CHILD).send().waitForResponse(1000).getPayloadString();
		Assert.assertEquals(CHILD_PAYLOAD, resp4);
		
		// Check that the resource is not found at the old URI
		System.out.println("Check that the resource is not found at the old URI");
		ResponseCode code1 = Request.newGet().setURI(base+NAME_1).send().waitForResponse(1000).getCode();
		Assert.assertEquals(ResponseCode.NOT_FOUND, code1);
		
		// Check that the child of (now) 'second' is not reachable under 'first'
		System.out.println("Check that the child of (now) 'second' is not reachable under 'first'");
		ResponseCode code2 = Request.newGet().setURI(base+NAME_1+"/"+CHILD).send().waitForResponse(1000).getCode();
		Assert.assertEquals(ResponseCode.NOT_FOUND, code2);
	}
	
	private void createServer() {
		CoapEndpoint endpoint = new CoapEndpoint(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
		
		resource = new TestResource(NAME_1, PAYLOAD);
		server = new CoapServer();
		server
			.add(new CoapResource(RES_A)
				.add(new CoapResource(RES_AA)
					.add(resource
						.add(new TestResource(CHILD, CHILD_PAYLOAD)))));

		server.addEndpoint(endpoint);
		server.start();
		serverPort = endpoint.getAddress().getPort();
	}
	
	private class TestResource extends CoapResource {
		
		private String payload;
		
		public TestResource(String name, String payload) {
			super(name);
			this.payload = payload;
		}
		
		@Override
		public void handleGET(CoapExchange exchange) {
			exchange.respond(ResponseCode.CONTENT, payload);
		}
	}
}
