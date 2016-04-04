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
 ******************************************************************************/
package org.eclipse.californium.core.test;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapHandler;
import org.eclipse.californium.core.CoapObserveRelation;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.MediaTypeRegistry;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


public class ClientAsynchronousTest {

	public static final String TARGET = "storage";
	public static final String CONTENT_1 = "one";
	public static final String CONTENT_2 = "two";
	public static final String CONTENT_3 = "three";
	public static final String CONTENT_4 = "four";
	public static final String QUERY_UPPER_CASE = "uppercase";
	
	private CoapServer server;
	private int serverPort;
	
	private CoapResource resource;
	
	private String expected;
	
	private List<String> failed = new CopyOnWriteArrayList<String>();
	private Throwable asyncThrowable = null;
	
	private AtomicInteger notifications = new AtomicInteger();
	
	@Before
	public void startupServer() {
		System.out.println("\nStart "+getClass().getSimpleName());
		NetworkConfig.getStandard()
			.setLong(NetworkConfig.Keys.MAX_TRANSMIT_WAIT, 100);
		createServer();
	}
	
	@After
	public void shutdownServer() {
		server.destroy();
		System.out.println("End "+getClass().getSimpleName());
	}
	
	volatile CoapResponse theResponse = null;
	
	@Test(timeout=5000)
	public void testAsynchronousCall() throws Exception {
	    final long timeLeap = 100;
	    final long timeout = 500;
		String uri = "coap://localhost:"+serverPort+"/"+TARGET;
		CoapClient client = new CoapClient(uri).useExecutor();
		
		// Check that we get the right content when calling get()
		client.get(new TestHandler("Test 1") {
			@Override public void onLoad(CoapResponse response) {
			    theResponse = response;
			}
		});
		while (theResponse == null) Thread.sleep(timeLeap);
        assertEquals(CONTENT_1, theResponse.getResponseText());
        theResponse = null;
		
		client.get(new TestHandler("Test 2") {
			@Override public void onLoad(CoapResponse response) {
			    theResponse = response;
			}
		});
		while (theResponse == null) Thread.sleep(timeLeap);
        assertEquals(CONTENT_1, theResponse.getResponseText());
        theResponse = null;
		
		// Change the content to "two" and check
		client.post(new TestHandler("Test 3") {
			@Override public void onLoad(CoapResponse response) {
			    theResponse = response;
			}
		}, CONTENT_2, MediaTypeRegistry.TEXT_PLAIN);
		while (theResponse == null) Thread.sleep(timeLeap);
        assertEquals(CONTENT_1, theResponse.getResponseText());
        theResponse = null;
		
		client.get(new TestHandler("Test 4") {
			@Override public void onLoad(CoapResponse response) {
			    theResponse = response;
			}
		});
		while (theResponse == null) Thread.sleep(timeLeap);
        assertEquals(CONTENT_2, theResponse.getResponseText());
        theResponse = null;
		
		// Observe the resource
		expected = CONTENT_2;
		CoapObserveRelation obs1 = client.observe(new TestHandler("Test Observe") {
			@Override public void onLoad(CoapResponse response) {
			    theResponse = response;
				notifications.incrementAndGet();
			}
		});
		
		for (int i = 0; i < 5; i++) {
		    while (theResponse == null) Thread.sleep(timeLeap);
		    assertEquals(expected, theResponse.getResponseText());
		    assertTrue("try #" + i, theResponse.advanced().getOptions().hasObserve());
		    theResponse = null;
		    resource.changed();
		}

		expected = CONTENT_3;
		client.post(new TestHandler("Test 5") {
			@Override public void onLoad(CoapResponse response) {
			    theResponse = response;
			}
		}, CONTENT_3, MediaTypeRegistry.TEXT_PLAIN);
		while (theResponse == null) Thread.sleep(100);
        assertEquals(CONTENT_2, theResponse.getResponseText());
        theResponse = null;
		
		// Try a put and receive a METHOD_NOT_ALLOWED
		client.put(new TestHandler("Test 6") {
			@Override public void onLoad(CoapResponse response) {
			    theResponse = response;
			}
		}, CONTENT_4, MediaTypeRegistry.TEXT_PLAIN);
		while (theResponse == null) Thread.sleep(timeLeap);
        assertEquals(ResponseCode.METHOD_NOT_ALLOWED, theResponse.getCode());
        theResponse = null;
		
		// Cancel observe relation of obs1 and check that it does no longer receive notifications
        obs1.reactiveCancel();
		Thread.sleep(timeout);
		assertNull(theResponse);
		expected = null; // The next notification would now cause a failure
		Thread.sleep(timeLeap);
		resource.changed();
		
		// Make another post
		client.post(new TestHandler("Test 7") {
			@Override public void onLoad(CoapResponse response) {
			    theResponse = response;
			}
		}, CONTENT_4, MediaTypeRegistry.TEXT_PLAIN);
		while (theResponse == null) Thread.sleep(timeLeap);
        assertEquals(CONTENT_3, theResponse.getResponseText());
        theResponse = null;
		
		// Try to use the builder and add a query
		new CoapClient.Builder("localhost", serverPort)
			.path(TARGET).query(QUERY_UPPER_CASE).create()
			.get(new TestHandler("Test 8") {
				@Override public void onLoad(CoapResponse response) {
				    theResponse = response;
				}
			}
		);
		while (theResponse == null) Thread.sleep(timeLeap);
        assertEquals(CONTENT_4.toUpperCase(), theResponse.getResponseText());
        theResponse = null;
		
		// Check that we indeed received 5 notifications
		// 1 from origin GET request, 3 x from changed(), 1 from post()
		Assert.assertEquals(7, notifications.get());
		
		Assert.assertTrue(failed.isEmpty());
		Assert.assertEquals(null, asyncThrowable);
	}
	
	private void assertEquals(Object expected, Object actual) {
		try {
			Assert.assertEquals(expected, actual);
		} catch (Throwable t) {
			t.printStackTrace();
			if (asyncThrowable == null)
				asyncThrowable = t;
		}
	}
	
	private void createServer() {
		CoapEndpoint endpoint = new CoapEndpoint(0);
		
		resource = new StorageResource(TARGET, CONTENT_1);
		server = new CoapServer();
		server.add(resource);

		server.addEndpoint(endpoint);
		server.start();
		serverPort = endpoint.getAddress().getPort();
	}
	
	private class StorageResource extends CoapResource {
		
		private String content;
		
		public StorageResource(String name, String content) {
			super(name);
			this.content = content;
			setObservable(true);
		}
		
		@Override
		public void handleGET(CoapExchange exchange) {
			List<String> queries = exchange.getRequestOptions().getUriQuery();
			String c = content;
			for (String q:queries)
				if (QUERY_UPPER_CASE.equals(q))
					c = content.toUpperCase();
			
			exchange.respond(ResponseCode.CONTENT, c);
		}
		
		@Override
		public void handlePOST(CoapExchange exchange) {
			String old = this.content;
			this.content = exchange.getRequestText();
			exchange.respond(ResponseCode.CHANGED, old);
			changed();
		}
	}
	
	private abstract class TestHandler implements CoapHandler {
		private String name;
		private TestHandler(String name) { this.name = name; }
		@Override public void onError() { failed.add(name); }
	}
}
