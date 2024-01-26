/*******************************************************************************
 * Copyright (c) 2022 Bosch IO GmbH and others.
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
 *    Bosch IO GmbH - initial implementation
 ******************************************************************************/
package org.eclipse.californium.core.observe;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.eclipse.californium.TestTools;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.coap.CoAP.Type;
import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.coap.Response;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.Endpoint;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.Exchange.Origin;
import org.eclipse.californium.core.server.resources.ObservableResource;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.util.DatagramWriter;
import org.eclipse.californium.elements.util.TestSynchroneExecutor;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@code ObserveRelation}.
 */
@Category(Small.class)
public class ObserveRelationTest {

	private static final int PEER_PORT = 13000;

	InetSocketAddress address;
	Endpoint localEndpoint;
	ObserveManager manager;
	Exchange exchange;
	Exchange exchange2;

	Type observeType;

	@Before
	public void setup() {
		address = new InetSocketAddress(InetAddress.getLoopbackAddress(), PEER_PORT);

		Configuration config = new Configuration();
		config.set(CoapConfig.MAX_SERVER_OBSERVES, 10);
		localEndpoint = mock(Endpoint.class);
		when(localEndpoint.getConfig()).thenReturn(config);

		manager = new ObserveManager(config);

		exchange = createExchange(0x123);
		exchange2 = createExchange(0x3210);

	}

	private Exchange createExchange(long token) {
		DatagramWriter writer = new DatagramWriter(8);
		writer.writeLong(token, Long.SIZE);
		Request request = Request.newGet();
		String uri = TestTools.getUri(address, "obs");
		request.setURI(uri);
		request.getOptions().setObserve(0);
		request.setSourceContext(request.getDestinationContext());
		request.setToken(writer.toByteArray());
		Exchange exchange = new Exchange(request, address, Origin.REMOTE, TestSynchroneExecutor.TEST_EXECUTOR);
		exchange.setEndpoint(localEndpoint);
		return exchange;
	}

	private ObserveRelation handleExchange(final Exchange exchange, final ResponseCode code, final Integer observe) {
		exchange.execute(new Runnable() {

			@Override
			public void run() {
				manager.addObserveRelation(exchange, resource);
				Response response = Response.createResponse(exchange.getRequest(), code);
				if (observe != null) {
					response.getOptions().setObserve(observe);
				}
				exchange.sendResponse(response);
				// dummy processing similar to the coap-stack
				exchange.setResponse(response);
				exchange.setCurrentResponse(response);
				ObserveRelation relation = exchange.getRelation();
				ObserveRelation.onResponse(relation, response);
			}
		});
		return exchange.getRelation();
	}

	@Test(expected = NullPointerException.class)
	public void testConstructorRejectsNull() {
		new ObserveRelation(manager, null, null);
	}

	@Test
	public void testNotEstablished() {
		exchange.execute(new Runnable() {

			@Override
			public void run() {
				manager.addObserveRelation(exchange, resource);
			}
		});
		assertThat(exchange.getRelation(), is(notNullValue()));
		assertThat(exchange.getRelation().getEndpoint().isEmpty(), is(false));
		assertThat(resource.getObserverCount(), is(0));
		exchange.getRelation().cancel();
		assertThat(exchange.getRelation().getEndpoint().isEmpty(), is(true));
	}

	@Test
	public void testEstablished() {
		handleExchange(exchange, ResponseCode.CONTENT, null);

		assertThat(exchange.getRelation(), is(notNullValue()));
		assertThat(exchange.getRelation().getEndpoint().isEmpty(), is(false));
		assertThat(exchange.getCurrentResponse().isNotification(), is(true));
		assertThat(resource.getObserverCount(), is(1));
		exchange.getRelation().cancel();
		assertThat(exchange.getRelation().getEndpoint().isEmpty(), is(true));
		assertThat(resource.getObserverCount(), is(0));
	}

	@Test
	public void testEstablishedWithObserveOption() {
		Integer observe = new Integer(100);
		handleExchange(exchange, ResponseCode.CONTENT, observe);

		assertThat(exchange.getRelation(), is(notNullValue()));
		assertThat(exchange.getRelation().getEndpoint().isEmpty(), is(false));
		assertThat(exchange.getCurrentResponse().getOptions().getObserve(), is(observe));
		assertThat(resource.getObserverCount(), is(1));
		exchange.getRelation().cancel();
		assertThat(exchange.getRelation().getEndpoint().isEmpty(), is(true));
		assertThat(resource.getObserverCount(), is(0));
	}

	@Test
	public void testNoSuccess() {
		handleExchange(exchange, ResponseCode.NOT_FOUND, null);

		assertThat(exchange.getRelation(), is(notNullValue()));
		assertThat(exchange.getRelation().getEndpoint().isEmpty(), is(false));
		assertThat(exchange.getCurrentResponse().isNotification(), is(false));
		assertThat(resource.getObserverCount(), is(0));
		exchange.getRelation().onSend(exchange.getCurrentResponse());
		assertThat(exchange.getRelation().getEndpoint().isEmpty(), is(true));
	}

	@Test
	public void testNoSuccessWithObserveOption() {
		Integer observe = new Integer(100);
		handleExchange(exchange, ResponseCode.NOT_FOUND, observe);

		assertThat(exchange.getRelation(), is(notNullValue()));
		assertThat(exchange.getRelation().getEndpoint().isEmpty(), is(false));
		assertThat(exchange.getCurrentResponse().isNotification(), is(false));
		assertThat(resource.getObserverCount(), is(0));
		exchange.getRelation().onSend(exchange.getCurrentResponse());
		assertThat(exchange.getRelation().getEndpoint().isEmpty(), is(true));
	}

	@Test
	public void testTwoObserves() {
		handleExchange(exchange, ResponseCode.CONTENT, null);
		handleExchange(exchange2, ResponseCode.CONTENT, null);

		assertThat(exchange.getRelation(), is(notNullValue()));
		assertThat(exchange.getRelation().getEndpoint().isEmpty(), is(false));

		assertThat(resource.getObserverCount(), is(2));
		exchange.getRelation().getEndpoint().cancelAll();
		assertThat(exchange.getRelation().getEndpoint().isEmpty(), is(true));
		assertThat(resource.getObserverCount(), is(0));
	}

	@Test
	public void testLimitObserves() {
		ObserveRelation relation = handleExchange(exchange, ResponseCode.CONTENT, null);
		ObserveRelation relation2 = handleExchange(exchange2, ResponseCode.CONTENT, null);
		long token = 1;
		Exchange exchangeN = createExchange(++token);
		while (handleExchange(exchangeN, ResponseCode.CONTENT, null) != null) {
			exchangeN = createExchange(++token);
		}
		assertThat(manager.isFull(), is(true));
		assertThat(exchangeN.getCurrentResponse().isNotification(), is(false));

		// replace
		Exchange exchangeM = createExchange(0x123);
		handleExchange(exchangeM, ResponseCode.CONTENT, null);
		assertThat(exchangeM.getRelation(), is(notNullValue()));
		assertThat(relation.isCanceled(), is(true));

		// cancel
		relation2.cancel();

		assertThat(manager.isFull(), is(false));
		exchangeN = createExchange(++token);
		handleExchange(exchangeN, ResponseCode.CONTENT, null);
		assertThat(exchangeN.getRelation(), is(notNullValue()));

		// cancel all
		relation.getEndpoint().cancelAll();
		assertThat(relation.getEndpoint().isEmpty(), is(true));
		assertThat(resource.getObserverCount(), is(0));
	}

	private ObservableResource resource = new ObservableResource() {

		private final List<ObserveRelation> observeRelations = new CopyOnWriteArrayList<>();

		@Override
		public boolean isObservable() {
			return true;
		}

		@Override
		public String getURI() {
			return "obs";
		}

		@Override
		public Type getObserveType() {
			return observeType;
		}

		@Override
		public int getNotificationSequenceNumber() {
			return 0;
		}

		@Override
		public void addObserveRelation(ObserveRelation relation) {
			observeRelations.add(relation);
		}

		@Override
		public void removeObserveRelation(ObserveRelation relation) {
			observeRelations.remove(relation);
		}

		@Override
		public int getObserverCount() {
			return observeRelations.size();
		}
	};

}
