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
 *    Bosch Software Innovations - initial creation
 ******************************************************************************/
package org.eclipse.californium.core.network;

import static org.junit.Assert.*;
import static org.eclipse.californium.TestTools.inRange;
import static org.hamcrest.CoreMatchers.*;
import java.net.InetSocketAddress;

import org.eclipse.californium.category.Small;
import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class InMemoryMessageIdProviderMulticastTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	private static final String GROUP = "224.0.1.187";
	private static final String GROUP2 = "224.0.1.188";
	private static final int PORT = 5683;

	/**
	 * this test verifies the miss configured network config file and returns no
	 * Message Id
	 */
	@Test
	public void testMulticastWithMissConfiguredNetworkConfig() {
		NetworkConfig config = network.createStandardTestConfig();
		config.setInt(NetworkConfig.Keys.MULTICAST_BASE_MID, 0);
		InMemoryMessageIdProvider midProvider = new InMemoryMessageIdProvider(config);
		assertEquals(midProvider.getNextMessageId(new InetSocketAddress(GROUP, PORT)), Message.NONE);
	}

	@Test
	public void testMidsWithTwoMulticastGroupsAtOnce() {
		final int multicastBaseMid = 65515;
		NetworkConfig config = network.createStandardTestConfig();
		config.setInt(NetworkConfig.Keys.EXCHANGE_LIFETIME, 1);
		config.setInt(NetworkConfig.Keys.MULTICAST_BASE_MID, multicastBaseMid);
		InMemoryMessageIdProvider midProvider = new InMemoryMessageIdProvider(config);
		for (int i = 1; i < 20; i++) {
			if ((i % 5) == 0) {
				try {
					Thread.sleep(1);
				} catch (InterruptedException e) {
				}
			}
			int multicastMidGroup1 = midProvider.getNextMessageId(new InetSocketAddress(GROUP, PORT));
			int multicastMidGroup2 = midProvider.getNextMessageId(new InetSocketAddress(GROUP2, PORT));
			String tag = "loop " + i + ":";
			assertThat(tag, multicastMidGroup1, is(inRange(multicastBaseMid, 65536)));
			assertThat(tag, multicastMidGroup2, is(inRange(multicastBaseMid, 65536)));
			assertThat(tag, multicastMidGroup1, is(not(multicastMidGroup2)));
		}
	}

	/**
	 * this test verifies the mid range of the configured Multicast and Non
	 * multicast MessageIdProviders
	 */
	@Test
	public void testMulticastMidRange() {
		final int multicastBaseMid = 20000;
		NetworkConfig config = network.createStandardTestConfig();
		config.setInt(NetworkConfig.Keys.EXCHANGE_LIFETIME, 1);
		config.setInt(NetworkConfig.Keys.MULTICAST_BASE_MID, multicastBaseMid);
		InetSocketAddress multicast = new InetSocketAddress(GROUP, PORT);
		InetSocketAddress unicast = new InetSocketAddress("127.0.0.1", PORT);
		InMemoryMessageIdProvider midProvider = new InMemoryMessageIdProvider(config);
		for (int i = 1; i < 100000; i++) {
			if ((i % 1000) == 0) {
				try {
					Thread.sleep(1);
				} catch (InterruptedException e) {
				}
			}
			int multicastMid = midProvider.getNextMessageId(multicast);
			int nonMulticastMid = midProvider.getNextMessageId(unicast);
			assertThat(multicastMid, is(inRange(multicastBaseMid, 65536)));
			assertThat(nonMulticastMid, is(inRange(0, multicastBaseMid)));
		}
	}
}
