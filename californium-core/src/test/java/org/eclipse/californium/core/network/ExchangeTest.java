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
 *    Bosch Software Innovations GmbH               - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.net.InetAddress;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.DummyEndpoint;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class ExchangeTest {

	private Exchange exchange;

	@Before
	public void setUp() {
		Request request = Request.newGet();
		request.setMID(1);
		request.setSourceContext(new AddressEndpointContext(InetAddress.getLoopbackAddress(), CoAP.DEFAULT_COAP_PORT));
		exchange = new Exchange(request, Origin.REMOTE, null);
		exchange.setEndpoint(new DummyEndpoint());
	}

	@Test
	public void testSetupDeliverDuplicate() {
		// setup to deliver one duplicate request
		assertTrue("could not setup deliver next duplicate", exchange.setupDeliverDuplicate(1));
		// setup to deliver one duplicate request,
		// but still haven't received that duplicate
		assertTrue("could not setup deliver next duplicate twice", exchange.setupDeliverDuplicate(1));
		// received duplicate, check delivery
		assertTrue("deliver next duplicate is disabled", exchange.checkDeliverDuplicate());
		// setup to deliver one duplicate request fails,
		// because this duplicate has already been received
		assertFalse("setup deliver next duplicate, should fail with threshold",
				exchange.setupDeliverDuplicate(1));
		// but setup to deliver a second duplicate request succeeds
		assertTrue("could not setup deliver second duplicate", exchange.setupDeliverDuplicate(2));
	}

	@Test
	public void testCheckDeliverDuplicate() {
		// check deliver duplicate default
		assertFalse("deliver duplicate should be disabled by default", exchange.checkDeliverDuplicate());
		// setup to deliver one duplicate request
		assertTrue("could not setup deliver next duplicate", exchange.setupDeliverDuplicate(1));
		// check deliver duplicate after setup
		assertTrue("deliver next duplicate is disabled", exchange.checkDeliverDuplicate());
		// check deliver next duplicate
		assertFalse("deliver second duplicate without setup is endabled", exchange.checkDeliverDuplicate());
		// setup to deliver second duplicate request
		assertTrue("could not setup deliver second duplicate", exchange.setupDeliverDuplicate(2));
		// check deliver duplicate after setup
		assertTrue("deliver second duplicate is disabled", exchange.checkDeliverDuplicate());
		// check deliver duplicate after setup
		assertFalse("deliver second duplicate without setup is enabled", exchange.checkDeliverDuplicate());
	}

	@Test
	public void testSetupDeliverDuplicateAfterAccept() {
		// setup to deliver one duplicate request
		assertTrue("could not setup deliver next duplicate", exchange.setupDeliverDuplicate(1));
		assertTrue("deliver next duplicate is disabled", exchange.checkDeliverDuplicate());
		exchange.sendAccept();
		assertFalse("could setup deliver next duplicate after accept the request", exchange.setupDeliverDuplicate(2));
	}

	@Test
	public void testSetupDeliverDuplicateAfterReject() {
		// setup to deliver one duplicate request
		assertTrue("could not setup deliver next duplicate", exchange.setupDeliverDuplicate(1));
		assertTrue("deliver next duplicate is disabled", exchange.checkDeliverDuplicate());
		exchange.sendReject();
		assertFalse("could setup deliver next duplicate after reject the request", exchange.setupDeliverDuplicate(2));
	}

	@Test
	public void testDeliverDuplicateAfterResponse() {
		// setup to deliver one duplicate request
		assertTrue("could not setup deliver next duplicate", exchange.setupDeliverDuplicate(1));
		Response response = Response.createResponse(exchange.getCurrentRequest(), CoAP.ResponseCode.CONTENT);
		exchange.sendResponse(response);
		assertFalse("could setup deliver next duplicate after response", exchange.setupDeliverDuplicate(1));
		assertFalse("deliver duplicate after response is enabled", exchange.checkDeliverDuplicate());
	}

	@Test
	public void testDeliverDuplicateNewResponse() {
		// setup to deliver one duplicate request
		assertTrue("could not setup deliver next duplicate", exchange.setupDeliverDuplicate(1));
		assertTrue("deliver next duplicate is disabled", exchange.checkDeliverDuplicate());
		assertFalse("setup deliver next duplicate, should fail with threshold",
				exchange.setupDeliverDuplicate(1));
		Request newRequest = Request.newGet();
		newRequest.setMID(exchange.getCurrentRequest().getMID() + 1);
		exchange.setCurrentRequest(newRequest);
		assertTrue("could not setup deliver next duplicate after new request", exchange.setupDeliverDuplicate(1));
		assertTrue("deliver next duplicate is disabled", exchange.checkDeliverDuplicate());
	}

	@Test(expected = IllegalStateException.class)
	public void testAcceptAfterSetupDeliverDuplicate() {
		// setup to deliver one duplicate request
		assertTrue("could not setup deliver next duplicate", exchange.setupDeliverDuplicate(1));
		exchange.sendAccept();
		assertFalse("could setup deliver next duplicate after accept the request", exchange.setupDeliverDuplicate(1));
		assertFalse("deliver duplicate after accept is enabled", exchange.checkDeliverDuplicate());
	}

	@Test(expected = IllegalStateException.class)
	public void testRejectAfterSetupDeliverDuplicate() {
		// setup to deliver one duplicate request
		assertTrue("could not setup deliver next duplicate", exchange.setupDeliverDuplicate(1));
		exchange.sendReject();
		assertFalse("could setup deliver next duplicate after reject the request", exchange.setupDeliverDuplicate(1));
		assertFalse("deliver duplicate after reject is enabled", exchange.checkDeliverDuplicate());
	}

}
