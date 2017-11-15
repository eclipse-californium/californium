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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add tests for different
 *                                                    MessageIdTracker modes
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;
import static org.eclipse.californium.core.network.MessageIdTracker.TOTAL_NO_OF_MIDS;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
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
	public void testNullTrackerGetNextMessageIdReturnsMid() {
		config.set(NetworkConfig.Keys.MID_TRACKER, "NULL");
		InMemoryMessageIdProvider provider = new InMemoryMessageIdProvider(config);
		InetSocketAddress peerAddress = getPeerAddress(1);
		int mid1 = provider.getNextMessageId(peerAddress);
		int mid2 = provider.getNextMessageId(peerAddress);
		assertThat(mid1, is(not(Message.NONE)));
		assertThat(mid2, is(not(Message.NONE)));
		assertThat(mid1, is(not(mid2)));
		for (int index = 0; index < TOTAL_NO_OF_MIDS * 2; ++index) {
			int mid = provider.getNextMessageId(peerAddress);
			assertThat(mid, is(not(Message.NONE)));
		}
	}

	@Test
	public void testMapBasedTrackerGetNextMessageIdReturnsMid() {
		config.set(NetworkConfig.Keys.MID_TRACKER, "MAPBASED");
		InMemoryMessageIdProvider provider = new InMemoryMessageIdProvider(config);
		testLimitedTrackerGetNextMessageIdReturnsMid(provider);
	}

	@Test
	public void testGroupedTrackerGetNextMessageIdReturnsMid() {
		config.set(NetworkConfig.Keys.MID_TRACKER, "GROUPED");
		InMemoryMessageIdProvider provider = new InMemoryMessageIdProvider(config);
		testLimitedTrackerGetNextMessageIdReturnsMid(provider);
	}

	private void testLimitedTrackerGetNextMessageIdReturnsMid(InMemoryMessageIdProvider provider) {
		InetSocketAddress peerAddress = getPeerAddress(1);
		int mid1 = provider.getNextMessageId(peerAddress);
		int mid2 = provider.getNextMessageId(peerAddress);
		assertThat(mid1, is(not(Message.NONE)));
		assertThat(mid2, is(not(Message.NONE)));
		assertThat(mid1, is(not(mid2)));
		int mid = provider.getNextMessageId(peerAddress);
		for (int index = 0; index < TOTAL_NO_OF_MIDS * 2; ++index) {
			mid = provider.getNextMessageId(peerAddress);
			if (Message.NONE == mid) {
				break;
			}
		}
		assertThat(mid, is(Message.NONE));
	}

	@Test(expected = IllegalArgumentException.class)
	public void testIllegalTracker() {
		config.set(NetworkConfig.Keys.MID_TRACKER, "ILLEGAL");
		InMemoryMessageIdProvider provider = new InMemoryMessageIdProvider(config);
		testLimitedTrackerGetNextMessageIdReturnsMid(provider);
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
