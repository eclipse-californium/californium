/*******************************************************************************
 * Copyright (c) 2015, 2016 Bosch Software Innovations GmbH and others.
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
 *    Achim Kraus (Bosch Software Innovations GmbH) - initial creation (465073)
 *    Achim Kraus (Bosch Software Innovations GmbH) - dummy setCorrelationContextMatcher
 *                                                    (fix GitHub issue #104)
 *    Achim Kraus (Bosch Software Innovations GmbH) - use CoapNetworkRule for
 *                                                    setup of test-network
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.hamcrest.core.IsSame.sameInstance;

import java.io.IOException;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.RawData;
import org.eclipse.californium.elements.RawDataChannel;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class EndpointManagerTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	@Before
	public void setUp() throws Exception {
		/* remove all endpoints, possibly changed by some other tests */
		EndpointManager.reset();
	}

	@Test
	public void testGetDefaultEndpoint() throws Exception {

		// WHEN get the default endpoint
		Endpoint endpoint = EndpointManager.getEndpointManager().getDefaultEndpoint();

		// THEN assert that the uri scheme is "coap:" and the endpoint is
		// started
		assertThat(endpoint, is(notNullValue()));
		assertThat(endpoint.getUri(), is(notNullValue()));
		assertThat(endpoint.getUri().getScheme(), is(CoAP.COAP_URI_SCHEME));
		assertThat(endpoint.isStarted(), is(true));
	}

	@Test
	public void testSetDefaultEndpoint() throws Exception {
		// GIVEN a old and a new endpoint
		Endpoint oldEndpoint = EndpointManager.getEndpointManager().getDefaultEndpoint();
		Endpoint endpoint = new CoapEndpoint();

		// WHEN set the new default endpoint
		EndpointManager.getEndpointManager().setDefaultEndpoint(endpoint);

		// THEN get the same new default endpoint and the old is stopped
		assertThat(EndpointManager.getEndpointManager().getDefaultEndpoint(), is(sameInstance(endpoint)));
		assertThat(oldEndpoint.isStarted(), is(false));
	}

	@Test
	public void testSetDefaultEndpointSchemeFailure() throws Exception {
		try {
			EndpointManager.getEndpointManager().setDefaultEndpoint(null);
			assertThat("null should fail", false);
		} catch (NullPointerException ex) {
		}
	}

	@Test
	public void testGetDefaultCoapEndpoint() throws Exception {
		// WHEN get the default endpoint
		Endpoint endpoint = EndpointManager.getEndpointManager().getDefaultEndpoint(CoAP.COAP_URI_SCHEME);

		// THEN assert that the uri scheme is "coap:" and the endpoint is
		// started
		assertThat(endpoint, is(notNullValue()));
		assertThat(endpoint.getUri(), is(notNullValue()));
		assertThat(endpoint.getUri().getScheme(), is(CoAP.COAP_URI_SCHEME));
		assertThat(endpoint.isStarted(), is(true));
	}

	@Test
	public void testGetDefaultCoapsEndpoint() throws Exception {
		// WHEN get the default endpoint
		Endpoint endpoint = EndpointManager.getEndpointManager().getDefaultEndpoint(CoAP.COAP_SECURE_URI_SCHEME);

		// THEN assert that the endpoint is not available
		assertThat(endpoint, is(nullValue()));
	}

	@Test
	public void testGetDefaultCoapOverTcpEndpoint() throws Exception {
		// WHEN get the default endpoint
		Endpoint endpoint = EndpointManager.getEndpointManager().getDefaultEndpoint(CoAP.COAP_TCP_URI_SCHEME);

		// THEN assert that the endpoint is not available
		assertThat(endpoint, is(nullValue()));
	}

	@Test
	public void testGetDefaultCoapsOverTcpEndpoint() throws Exception {
		// WHEN get the default endpoint
		Endpoint endpoint = EndpointManager.getEndpointManager().getDefaultEndpoint(CoAP.COAP_SECURE_TCP_URI_SCHEME);

		// THEN assert that the endpoint is not available
		assertThat(endpoint, is(nullValue()));
	}

	private static class DummyHttpConnector implements Connector {

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
		public void send(RawData msg) {
		}

		@Override
		public void setRawDataReceiver(RawDataChannel messageHandler) {
		}

		@Override
		public void setEndpointContextMatcher(EndpointContextMatcher strategy) {
		}

		@Override
		public InetSocketAddress getAddress() {
			return null;
		}

		@Override
		public String getProtocol() {
			return "HTTP";
		}

		@Override
		public String toString() {
			return getProtocol() + "-" + getAddress();
		}
	}
}
