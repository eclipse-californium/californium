/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.server;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.coap.CoAP.Code;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.Option;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.server.resources.Resource;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;


/**
 * Verifies behavior of {@link ServerMessageDeliverer}.
 *
 */
public class ServerMessageDelivererTest {

	private Resource rootResource;
	private Exchange incomingRequest;
	private Response incomingResponse;
	private Exchange outboundRequest;

	/**
	 * Sets up the fixture.
	 */
	@Before
	public void setUp() {
		rootResource = mock(Resource.class);
		when(rootResource.getChild(anyString())).thenReturn(rootResource);
		when(rootResource.getExecutor()).thenReturn(null);
		incomingRequest = new Exchange(new Request(Code.POST), Exchange.Origin.REMOTE);
		incomingRequest.setRequest(incomingRequest.getCurrentRequest());
		incomingResponse = new Response(ResponseCode.CONTENT);
		outboundRequest = new Exchange(new Request(Code.GET), Origin.LOCAL);
		outboundRequest.setRequest(outboundRequest.getCurrentRequest());
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
		ServerMessageDeliverer deliverer = new ServerMessageDeliverer(rootResource) {
			@Override
			protected boolean preDeliverRequest(Exchange exchange) {
				Response response = new Response(ResponseCode.CREATED);
				exchange.setResponse(response);
				return true;
			}
		};

		// WHEN a request is received
		deliverer.deliverRequest(incomingRequest);

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
		final Option customOption = new Option(200);
		ServerMessageDeliverer deliverer = new ServerMessageDeliverer(rootResource) {
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
		assertTrue(exchangeCaptor.getValue().getRequest().getOptions().hasOption(200));
	}

	/**
	 * Verifies that incoming responses are not delivered to their originating requests
	 * if a subclass has already processed the response.
	 */
	@Test
	public void testDeliverResponseYieldsToSubclass() {

		// GIVEN a message deliverer subclass that processes all incoming responses
		ServerMessageDeliverer deliverer = new ServerMessageDeliverer(rootResource) {

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
		ServerMessageDeliverer deliverer = new ServerMessageDeliverer(rootResource) {

			@Override
			protected boolean preDeliverResponse(Exchange exchange, Response response) {
				response.getOptions().addOption(new Option(200));
				return false;
			}
		};

		// WHEN a response is received
		deliverer.deliverResponse(outboundRequest, incomingResponse);

		// THEN the response is delivered to the request
		assertNotNull(outboundRequest.getRequest().getResponse());
		// and the response contains the custom option
		assertTrue(outboundRequest.getRequest().getResponse().getOptions().hasOption(200));
	}
}
