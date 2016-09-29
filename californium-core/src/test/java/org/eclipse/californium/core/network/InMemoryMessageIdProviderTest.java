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
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 * Verifies behavior of {@code InMemoryMessageIdProvider}.
 *
 */
@Category(Small.class)
public class InMemoryMessageIdProviderTest {

	NetworkConfig config;

	@Before
	public void setup() {
		config = NetworkConfig.createStandardWithoutFile();
	}

	@Test
	public void testGetNextMessageIdReturnsMid() {

		InMemoryMessageIdProvider provider = new InMemoryMessageIdProvider(config);
		InetSocketAddress peerAddress = getPeerAddress(1);
		int mid1 = provider.getNextMessageId(peerAddress);
		int mid2 = provider.getNextMessageId(peerAddress);
		assertThat(mid1, is(not(-1)));
		assertThat(mid2, is(not(-1)));
		assertThat(mid1, is(not(mid2)));
	}

	@Test
	public void testGetNextMessageIdFailsIfMaxPeersIsReached() {

		int MAX_PEERS = 2;
		config.setLong(NetworkConfig.Keys.MAX_ACTIVE_PEERS, MAX_PEERS);
		InMemoryMessageIdProvider provider = new InMemoryMessageIdProvider(config);
		addPeers(provider, MAX_PEERS);

		assertThat(
				"Should not have been able to add more peers",
				provider.getNextMessageId(getPeerAddress(MAX_PEERS + 1)),
				is(-1));
	}

	private static void addPeers(final MessageIdProvider provider, final int peerCount) {
		for (int i = 0; i < peerCount; i++) {
			provider.getNextMessageId(getPeerAddress(i));
		}
	}

	private static InetSocketAddress getPeerAddress(final int i) {

		try {
			InetAddress addr = InetAddress.getByAddress(new byte[]{(byte) 192, (byte) 168, 0, (byte) i});
			return new InetSocketAddress(addr, CoAP.DEFAULT_COAP_PORT);
		} catch (UnknownHostException e) {
			// should not happen
			return null;
		}
	}
}
