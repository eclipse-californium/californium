/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 *    Achim Kraus (Bosch Software Innovations GmbH) - add category
 ******************************************************************************/
package org.eclipse.californium.core.server;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.option.EmptyOptionDefinition;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.server.resources.Resource;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.util.TestSynchroneExecutor;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.mockito.ArgumentCaptor;


/**
 * Verifies behavior of {@link ServerMessageDeliverer}.
 */
@Category(Small.class)
public class ServerMessageDelivererTest {
	public final EmptyOptionDefinition CUSTOM = new EmptyOptionDefinition(200, "Test");
	
	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	private Resource rootResource;
	private Exchange incomingRequest;
	private Response incomingResponse;
	private Exchange outboundRequest;

	/**
	 * Sets up the fixture.
	 */
	@Before
	public void setUp() {
		InetSocketAddress dest = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5683);
		rootResource = mock(Resource.class);
		when(rootResource.getChild(anyString())).thenReturn(rootResource);
		when(rootResource.getExecutor()).thenReturn(null);
		incomingRequest = new Exchange(new Request(Code.POST), dest, Exchange.Origin.REMOTE, TestSynchroneExecutor.TEST_EXECUTOR);
		incomingResponse = new Response(ResponseCode.CONTENT);
		outboundRequest = new Exchange(new Request(Code.GET), dest, Origin.LOCAL, TestSynchroneExecutor.TEST_EXECUTOR);
	}

	/**
	 * Verifies that the message deliverer does not deliver incoming
	 * requests to resources if a subclass has already processed the
	 * request.
	 */
	@Test
	public void testDeliverRequestYieldsToSubclass() {

		// GIVEN a message deliverer subclass which processes all incoming requests
		// in its preDeliverRequest method
		final ServerMessageDeliverer deliverer = new ServerMessageDeliverer(rootResource, null) {
			@Override
			protected boolean preDeliverRequest(Exchange exchange) {
				Response response = new Response(ResponseCode.CREATED);
				exchange.setResponse(response);
				return true;
			}
		};

		// WHEN a request is received
		incomingRequest.execute(new Runnable() {
			
			@Override
			public void run() {
				deliverer.deliverRequest(incomingRequest);
			}
		});

		// THEN the request is not delivered to the match-all root resource
		verify(rootResource, never()).handleRequest(incomingRequest);
		verify(rootResource, never()).getChild(anyString());
	}

	/**
	 * Verifies that the message deliverer delivers incoming
	 * requests to resources if a subclass has not yet processed the response.
	 */
	@Test
	public void testDeliverRequestProcessesRequestAfterPreDeliverRequest() {

		// GIVEN a message deliverer subclass that adds a custom option to incoming
		// requests
		final Option customOption = new Option(CUSTOM);
		ServerMessageDeliverer deliverer = new ServerMessageDeliverer(rootResource, null) {
			@Override
			protected boolean preDeliverRequest(Exchange exchange) {
				exchange.getRequest().getOptions().addOption(customOption);
				return false;
			}
		};

		// WHEN a request is received
		deliverer.deliverRequest(incomingRequest);

		// THEN the request is delivered to the match-all root resource
		ArgumentCaptor<Exchange> exchangeCaptor = ArgumentCaptor.forClass(Exchange.class);
		verify(rootResource).handleRequest(exchangeCaptor.capture());
		// and the request contains the custom option
		assertTrue(exchangeCaptor.getValue().getRequest().getOptions().hasOption(CUSTOM));
	}

	/**
	 * Verifies that incoming responses are not delivered to their originating requests
	 * if a subclass has already processed the response.
	 */
	@Test
	public void testDeliverResponseYieldsToSubclass() {

		// GIVEN a message deliverer subclass that processes all incoming responses
		ServerMessageDeliverer deliverer = new ServerMessageDeliverer(rootResource, null) {

			@Override
			protected boolean preDeliverResponse(Exchange exchange, Response response) {
				return true;
			}
		};

		// WHEN a response is received
		deliverer.deliverResponse(outboundRequest, incomingResponse);

		// THEN the response is not delivered to the request
		assertNull(outboundRequest.getRequest().getResponse());
	}

	/**
	 * Verifies that incoming responses are delivered to their originating requests
	 * if a subclass has not already processed the response.
	 */
	@Test
	public void testDeliverResponseProcessesResponseAfterPreDeliverResponse() {

		// GIVEN a message deliverer subclass that adds a custom option to incoming
		// responses
		ServerMessageDeliverer deliverer = new ServerMessageDeliverer(rootResource, null) {

			@Override
			protected boolean preDeliverResponse(Exchange exchange, Response response) {
				response.getOptions().addOption(new Option(CUSTOM));
				return false;
			}
		};

		// WHEN a response is received
		deliverer.deliverResponse(outboundRequest, incomingResponse);

		// THEN the response is delivered to the request
		assertNotNull(outboundRequest.getRequest().getResponse());
		// and the response contains the custom option
		assertTrue(outboundRequest.getRequest().getResponse().getOptions().hasOption(CUSTOM));
	}
}
