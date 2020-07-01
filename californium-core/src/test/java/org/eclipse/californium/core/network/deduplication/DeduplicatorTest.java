/*******************************************************************************
 * Copyright (c) 2019 Bosch Software Innovations GmbH and others.
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
package org.eclipse.californium.core.network.deduplication;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Arrays;

import org.eclipse.californium.core.coap.Request;
import org.eclipse.californium.core.network.Exchange;
import org.eclipse.californium.core.network.KeyMID;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.AddressEndpointContext;
import org.eclipse.californium.elements.category.Small;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
@Category(Small.class)
public class DeduplicatorTest {

	private static final InetSocketAddress PEER = new InetSocketAddress(InetAddress.getLoopbackAddress(), 5683);

	/**
	 * Actual deduplicator mode.
	 */
	@Parameter
	public String mode;

	/**
	 * @return List of deduplicator modes.
	 */
	@Parameters(name = "deduplicator = {0}")
	public static Iterable<String> deduplicatorParams() {
		return Arrays.asList(NetworkConfig.Keys.DEDUPLICATOR_MARK_AND_SWEEP,
				NetworkConfig.Keys.DEDUPLICATOR_PEERS_MARK_AND_SWEEP,
				NetworkConfig.Keys.DEDUPLICATOR_CROP_ROTATION);
	}

	KeyMID key;
	Exchange exchange1;
	Exchange exchange2;
	Exchange exchange3;
	Deduplicator deduplicator;

	@Before
	public void init() {
		NetworkConfig config = new NetworkConfig();
		config.set(NetworkConfig.Keys.DEDUPLICATOR, mode);
		deduplicator = DeduplicatorFactory.getDeduplicatorFactory().createDeduplicator(config);
		Request incoming = Request.newGet();
		incoming.setMID(10);
		incoming.setSourceContext(new AddressEndpointContext(PEER));
		key = new KeyMID(incoming.getMID(), PEER);
		exchange1 = new Exchange(incoming, Exchange.Origin.REMOTE, null);
		exchange2 = new Exchange(incoming, Exchange.Origin.REMOTE, null);
		incoming = Request.newGet();
		incoming.setMID(10);
		incoming.setSourceContext(new AddressEndpointContext(PEER));
		exchange3 = new Exchange(incoming, Exchange.Origin.REMOTE, null);
	}

	@Test
	public void testFindPreviousFirstTime() throws Exception {
		assertThat(deduplicator.findPrevious(key, exchange1), is(nullValue()));
	}

	@Test
	public void testFindPreviousSecondTime() throws Exception {
		assertThat(deduplicator.findPrevious(key, exchange1), is(nullValue()));
		assertThat(deduplicator.findPrevious(key, exchange2), is(exchange1));
	}

	@Test
	public void testReplacePreviousFirstTime() throws Exception {
		assertThat(deduplicator.replacePrevious(key, exchange1, exchange2), is(true));
		assertThat(deduplicator.find(key), is(exchange2));
	}

	@Test
	public void testReplacePreviousSecondTime() throws Exception {
		assertThat(deduplicator.findPrevious(key, exchange1), is(nullValue()));
		assertThat(deduplicator.replacePrevious(key, exchange1, exchange2), is(true));
		assertThat(deduplicator.find(key), is(exchange2));
	}

	@Test
	public void testReplacePreviousSecondTimeAltered() throws Exception {
		assertThat(deduplicator.findPrevious(key, exchange1), is(nullValue()));
		assertThat(deduplicator.replacePrevious(key, exchange1, exchange3), is(true));
		assertThat(deduplicator.replacePrevious(key, exchange1, exchange2), is(false));
		assertThat(deduplicator.find(key), is(exchange3));
	}
}
