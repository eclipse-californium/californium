/*******************************************************************************
 * Copyright (c) 2018 Bosch Software Innovations GmbH and others.
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

import static org.eclipse.californium.elements.util.TestConditionTools.inRange;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;

import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;

import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.elements.category.Small;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.TestTimeRule;
import org.eclipse.californium.rule.CoapNetworkRule;
import org.eclipse.californium.rule.CoapThreadsRule;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(Small.class)
public class InMemoryMessageIdProviderMulticastTest {

	@ClassRule
	public static CoapNetworkRule network = new CoapNetworkRule(CoapNetworkRule.Mode.DIRECT,
			CoapNetworkRule.Mode.NATIVE);

	@Rule
	public CoapThreadsRule cleanup = new CoapThreadsRule();

	@Rule
	public TestTimeRule time = new TestTimeRule();

	private static final String GROUP = "224.0.1.187";
	private static final String GROUP2 = "224.0.1.188";
	private static final int PORT = 5683;

	/**
	 * this test verifies the miss configured network config file and throws a 
	 * IllegalArgumentException.
	 */
	@Test(expected = IllegalStateException.class)
	public void testMulticastWithMissConfiguredNetworkConfig() {
		Configuration config = network.createStandardTestConfig();
		config.set(CoapConfig.MULTICAST_BASE_MID, 0);
		InMemoryMessageIdProvider midProvider = new InMemoryMessageIdProvider(config);
		midProvider.getNextMessageId(new InetSocketAddress(GROUP, PORT));
	}

	@Test
	public void testMidsWithTwoMulticastGroupsAtOnce() {
		final int multicastBaseMid = 65515;
		Configuration config = network.createStandardTestConfig();
		config.set(CoapConfig.MULTICAST_BASE_MID, multicastBaseMid);
		InMemoryMessageIdProvider midProvider = new InMemoryMessageIdProvider(config);
		for (int i = 1; i < 20; i++) {
			if ((i % 5) == 0) {
				time.addTestTimeShift(config.getTimeAsInt(CoapConfig.EXCHANGE_LIFETIME, TimeUnit.MILLISECONDS) + 1, TimeUnit.MILLISECONDS);
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
		Configuration config = network.createStandardTestConfig();
		config.set(CoapConfig.EXCHANGE_LIFETIME, 1, TimeUnit.MILLISECONDS);
		config.set(CoapConfig.MULTICAST_BASE_MID, multicastBaseMid);
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
