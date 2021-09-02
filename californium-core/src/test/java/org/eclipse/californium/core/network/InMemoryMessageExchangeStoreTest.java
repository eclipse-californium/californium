/*******************************************************************************
 * Copyright (c) 2016 Bosch Software Innovations GmbH and others.
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
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.net.InetAddress;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.ExecutorsUtil;
import org.eclipse.californium.elements.util.TestSynchroneExecutor;
import org.eclipse.californium.elements.util.TestThreadFactory;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;


/**
 * Verifies behavior of the {@link InMemoryMessageExchangeStore} class.
 *
 */
@Category(Small.class)
public class InMemoryMessageExchangeStoreTest {
	private static final int PEER_PORT = 12000;

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	InMemoryMessageExchangeStore store;
	Configuration config;

	@Before
	public void createConfig() {
		ScheduledExecutorService executor = ExecutorsUtil.newSingleThreadScheduledExecutor(new TestThreadFactory("ExchangeStore-"));
		cleanup.add(executor);
		config = Configuration.createStandardWithoutFile();
		config.set(CoapConfig.EXCHANGE_LIFETIME, 200, TimeUnit.MILLISECONDS);
		store = new InMemoryMessageExchangeStore(config);
		store.setExecutor(executor);
		store.start();
	}

	@After
	public void stop() {
		store.stop();
	}

	@Test
	public void testRegisterOutboundRequestAssignsMid() {

		final Exchange exchange = newOutboundRequest();

		// WHEN registering the outbound request
		exchange.execute(new Runnable() {
			
			@Override
			public void run() {
				store.registerOutboundRequest(exchange);
			}
		});

		// THEN the request gets assigned an MID and is put to the store
		assertNotNull(exchange.getCurrentRequest().getMID());
		KeyMID key = new KeyMID(exchange.getCurrentRequest().getMID(), exchange.getPeersIdentity());
		assertThat(store.get(key), is(exchange));
	}

	@Test
	public void testRegisterOutboundRequestRejectsOtherRequestWithAlreadyUsedMid() {

		final Exchange exchange = newOutboundRequest();
		exchange.execute(new Runnable() {
			
			@Override
			public void run() {
				store.registerOutboundRequest(exchange);
			}
		});

		// WHEN registering another request with the same MID
		final Exchange newExchange = newOutboundRequest(exchange.getCurrentRequest().getMID());
		newExchange.execute(new Runnable() {
			
			@Override
			public void run() {
				try {
					store.registerOutboundRequest(newExchange);
					fail("should have thrown IllegalArgumentException");
				} catch (IllegalArgumentException e) {
					// THEN the newExchange is not put to the store
					KeyMID key = new KeyMID(exchange.getCurrentRequest().getMID(),
							exchange.getPeersIdentity());
					Exchange exchangeFromStore = store.get(key);
					assertThat(exchangeFromStore, is(exchange));
					assertThat(exchangeFromStore, is(not(newExchange)));
				}
			}
		});
	}

	@Test
	public void testRegisterOutboundRequestRejectsMultipleRegistrationOfSameRequest() {

		final Exchange exchange = newOutboundRequest();
		exchange.execute(new Runnable() {
			
			@Override
			public void run() {
				store.registerOutboundRequest(exchange);
			}
		});

		// WHEN registering the same request again
		exchange.execute(new Runnable() {
			
			@Override
			public void run() {
				try {
					store.registerOutboundRequest(exchange);
					fail("should have thrown IllegalArgumentException");
				} catch (IllegalArgumentException e) {
					// THEN the store rejects the re-registration
				}
			}
		});
	}

	@Test(expected = NullPointerException.class)
	public void testShouldNotCreateInMemoryMessageExchangeStoreWithoutTokenProvider() {
		// WHEN trying to create new InMemoryMessageExchangeStore without TokenProvider
		store = new InMemoryMessageExchangeStore(config, null);
	}

	@Test
	public void testRegisterOutboundRequestAcceptsRetransmittedRequest() {

		final Exchange exchange = newOutboundRequest();
		exchange.execute(new Runnable() {
			
			@Override
			public void run() {
				store.registerOutboundRequest(exchange);
			}
		});

		// WHEN registering the same request as a re-transmission
		exchange.execute(new Runnable() {
			
			@Override
			public void run() {
				exchange.incrementFailedTransmissionCount();
				store.registerOutboundRequest(exchange);
			}
		});

		// THEN the store contains the re-transmitted request
		KeyMID key = new KeyMID(exchange.getCurrentRequest().getMID(),
				exchange.getPeersIdentity());
		Exchange exchangeFromStore = store.get(key);
		assertThat(exchangeFromStore, is(exchange));
		assertThat(exchangeFromStore.getFailedTransmissionCount(), is(1));
	}

	private Exchange newOutboundRequest(int... mid) {
		Request request = Request.newGet();
		String uri = TestTools.getUri(InetAddress.getLoopbackAddress(), PEER_PORT, "test");
		request.setURI(uri);
		if (mid.length > 0) {
			request.setMID(mid[0]);
		}
		Exchange exchange = new Exchange(request, request.getDestinationContext().getPeerAddress(), Origin.LOCAL, TestSynchroneExecutor.TEST_EXECUTOR);
		return exchange;
	}
}
