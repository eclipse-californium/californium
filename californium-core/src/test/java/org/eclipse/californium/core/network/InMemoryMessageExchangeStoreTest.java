/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
package org.eclipse.californium.core.network;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.net.InetAddress;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.network.Exchange.KeyMID;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Verifies behavior of the {@link InMemoryMessageExchangeStore} class.
 *
 */
@Category(Small.class)
public class InMemoryMessageExchangeStoreTest {

	/**
	 * 
	 */
	private static final int PEER_PORT = 12000;
	InMemoryMessageExchangeStore store;
	NetworkConfig config;

	@Before
	public void createConfig() {
		config = NetworkConfig.createStandardWithoutFile();
		config.setLong(NetworkConfig.Keys.EXCHANGE_LIFETIME, 200); //ms
		store = new InMemoryMessageExchangeStore(config);
		store.start();
	}

	@After
	public void stop() {
		store.stop();
	}

	@Test
	public void testRegisterOutboundRequestAssignsMid() {

		Exchange exchange = newOutboundRequest();

		// WHEN registering the outbound request
		store.registerOutboundRequest(exchange);

		// THEN the request gets assigned an MID and is put to the store
		assertNotNull(exchange.getCurrentRequest().getMID());
		KeyMID key = KeyMID.fromOutboundMessage(exchange.getCurrentRequest());
		assertThat(store.get(key), is(exchange));
	}

	@Test
	public void testRegisterOutboundRequestRejectsOtherRequestWithAlreadyUsedMid() {

		Exchange exchange = newOutboundRequest();
		store.registerOutboundRequest(exchange);

		// WHEN registering another request with the same MID
		Exchange newExchange = newOutboundRequest();
		newExchange.getCurrentRequest().setMID(exchange.getCurrentRequest().getMID());
		try {
			store.registerOutboundRequest(newExchange);
			fail("should have thrown IllegalArgumentException");
		} catch (IllegalArgumentException e) {
			// THEN the newExchange is not put to the store
			KeyMID key = KeyMID.fromOutboundMessage(exchange.getCurrentRequest());
			Exchange exchangeFromStore = store.get(key);
			assertThat(exchangeFromStore, is(exchange));
			assertThat(exchangeFromStore, is(not(newExchange)));
		}
	}

	@Test
	public void testRegisterOutboundRequestRejectsMultipleRegistrationOfSameRequest() {

		Exchange exchange = newOutboundRequest();
		store.registerOutboundRequest(exchange);

		// WHEN registering the same request again
		try {
			store.registerOutboundRequest(exchange);
			fail("should have thrown IllegalArgumentException");
		} catch (IllegalArgumentException e) {
			// THEN the store rejects the re-registration
		}
	}

	public void testRegisterOutboundRequestAcceptsRetransmittedRequest() {

		Exchange exchange = newOutboundRequest();
		store.registerOutboundRequest(exchange);

		// WHEN registering the same request as a re-transmission
		exchange.setFailedTransmissionCount(1);
		store.registerOutboundRequest(exchange);

		// THEN the store contains the re-transmitted request
		KeyMID key = KeyMID.fromOutboundMessage(exchange.getCurrentRequest());
		Exchange exchangeFromStore = store.get(key);
		assertThat(exchangeFromStore, is(exchange));
		assertThat(exchangeFromStore.getFailedTransmissionCount(), is(1));
	}

	private Exchange newOutboundRequest() {
		Request request = Request.newGet();
		request.setURI("coap://127.0.0.1:12000/test");
		Exchange exchange = new Exchange(request, Origin.LOCAL);
		return exchange;
	}
}
