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
 *    Achim Kraus (Bosch Software Innovations GmbH) - add tests for different
 *                                                    MessageIdTracker modes
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.eclipse.californium.core.network.MessageIdTracker.TOTAL_NO_OF_MIDS;
import static org.eclipse.californium.elements.util.TestConditionTools.inRange;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.elements.util.ExpectedExceptionWrapper;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;

/**
 * Verifies behavior of {@code InMemoryMessageIdProvider}.
 *
 */
@Category(Small.class)
public class InMemoryMessageIdProviderTest {
	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT, CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public ExpectedException exception = ExpectedExceptionWrapper.none();

	@Rule
	public TestTimeRule time = new TestTimeRule();

	private NetworkConfig config = network.createStandardTestConfig();

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
			assertThat(mid, is(inRange(0, TOTAL_NO_OF_MIDS)));
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

		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("No MID available, all"));

		provider.getNextMessageId(peerAddress);
		for (int index = 0; index < TOTAL_NO_OF_MIDS * 2; ++index) {
			try {
				provider.getNextMessageId(peerAddress);
			} catch (IllegalStateException ex) {
				System.out.println(ex.getMessage());
				throw ex;
			}
		}
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

		exception.expect(IllegalStateException.class);
		exception.expectMessage(containsString("No MID available, max."));

		try {
			provider.getNextMessageId(getPeerAddress(MAX_PEERS + 1));
		} catch (IllegalStateException ex) {
			System.out.println(ex.getMessage());
			throw ex;
		}
	}

	@Test
	public void testGetNextMessageIdIfMaxPeersIsReachedWithStaleEntry() throws InterruptedException {

		int MAX_PEERS = 2;
		int MAX_PEER_INACTIVITY_PERIOD = 1; // seconds
		config.setLong(NetworkConfig.Keys.MAX_ACTIVE_PEERS, MAX_PEERS);
		config.setLong(NetworkConfig.Keys.MAX_PEER_INACTIVITY_PERIOD, MAX_PEER_INACTIVITY_PERIOD);
		InMemoryMessageIdProvider provider = new InMemoryMessageIdProvider(config);
		addPeers(provider, MAX_PEERS);

		time.addTestTimeShift(MAX_PEER_INACTIVITY_PERIOD * 1200, TimeUnit.MILLISECONDS);

		assertThat(provider.getNextMessageId(getPeerAddress(MAX_PEERS + 1)), is(not(-1)));
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
