/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial implementation
 ******************************************************************************/
package org.eclipse.californium.rule;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.elements.rule.NetworkRule;
import org.eclipse.californium.elements.util.DatagramFormatter;

/**
 * CoAP network rules for junit test using datagram sockets.
 * 
 * Though {@link NetworkConfig} and {@link EndpointManager} depend on some
 * internal state, this rule manages these states by setup and cleanup the
 * values. Therefore it's intended, that test code uses the provided methods to
 * access {@link NetworkConfig}, {@link #getStandardTestConfig()},
 * {@link #createStandardTestConfig()}, and {@link #createTestConfig()}.
 *
 * The rule is intended to be mainly used as <code>&#64;ClassRule<code>
 * 
 * <pre>
 * public class AbcNetworkTest {
 *    &#64;ClassRule
 *    public static CoapNetworkRule network = new CoapNetworkRule(Mode.DIRECT, Mode.NATIVE);
 *    ...
 *    &#64;BeforeClass
 *    public static void init() {
 *       network.getStandardTestConfig().setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 32);
 *    ...
 * </pre>
 * 
 * The {@link NetworkConfig} access methods then are valid from the
 * <code>&#64;BeforeClass</code> until <code>&#64;AfterClass</code> method.
 * 
 * If used as
 * <code>&#64;Rule<code>, the {@link NetworkConfig} access methods then are valid from the
 * <code>&#64;Before</code> until <code>&#64;After</code> method.
 * 
 * For the DIRECT mode there are additional parameters available
 * {@link #setMessageThreads(int)}, and {@link #setDelay(int)}.
 * 
 * In rare cases nested rules are allowed, but be careful when accessing the
 * {@link NetworkConfig} to choose the active rule. The inner will overwrite the
 * outer {@link NetworkConfig} and detach from that.

 * <pre>
 * public class AbcNetworkTest {
 *    &#64;ClassRule
 *    public static CoapNetworkRule network = new CoapNetworkRule(Mode.DIRECT, Mode.NATIVE);
 *    &#64;Rule
 *    public static CoapNetworkRule inner = new CoapNetworkRule(Mode.DIRECT, Mode.NATIVE);
 *    ...
 *    &#64;BeforeClass
 *    public static void init() {
 *       network.getStandardTestConfig().setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 32);
 *    ...
 *    
 *    &#64;Before
 *    public void before() {
 *       inner.getStandardTestConfig().setInt(NetworkConfig.Keys.MAX_MESSAGE_SIZE, 64);
 *    
 * </pre>
 * 
 */
public class CoapNetworkRule extends NetworkRule {

	public static final Logger LOGGER = Logger.getLogger(CoapNetworkRule.class.getName());
	private static final int DEFAULT_MESSAGE_THREADS = 1;
	/**
	 * CoAP datagram formatter. Used for logging.
	 */
	private static final DatagramFormatter FORMATTER = new DatagramFormatter() {

		private DataParser parser = new UdpDataParser();

		@Override
		public String format(byte[] data) {
			if (null == data) {
				return "<null>";
			} else if (0 == data.length) {
				return "[] (empty)";
			}
			try {
				Message message = parser.parseMessage(data);
				return message.toString();
			} catch (RuntimeException ex) {
				return "decode " + data.length + " received bytes with " + ex.getMessage();
			}
		}

	};

	/**
	 * Number of message processing threads. Used to setup test
	 * {@link NetworkConfig}.
	 * 
	 * @see #createTestConfig()
	 * @see #createStandardTestConfig()
	 * @see #getStandardTestConfig()
	 */
	private final AtomicInteger messageThreads = new AtomicInteger(DEFAULT_MESSAGE_THREADS);

	/**
	 * Create rule supporting provided modes.
	 * 
	 * @param modes
	 *            supported datagram socket implementation modes.
	 */
	public CoapNetworkRule(Mode... modes) {
		super(FORMATTER, modes);
		this.messageThreads.set(DEFAULT_MESSAGE_THREADS);
	}

	/**
	 * Set number of message processing threads. Using multiple threads for
	 * sending and receiving may result in reordering of messages. Therefore the
	 * default is {@link #DEFAULT_MESSAGE_THREADS} to ensure, that no such
	 * reorder happens.
	 * 
	 * @param threads
	 *            number of threads.
	 * @return this rule
	 */
	public CoapNetworkRule setMessageThreads(int threads) {
		if (1 > threads) {
			throw new IllegalArgumentException("number of message threads must be at least 1, not " + threads + "!");
		}
		messageThreads.set(threads);
		return this;
	}

	@Override
	public CoapNetworkRule setDelay(int delayInMillis) {
		return (CoapNetworkRule) super.setDelay(delayInMillis);
	}

	@Override
	protected void initNetwork(boolean first) {
		if (first) {
			EndpointManager.reset();
		}
		createStandardTestConfig();
		super.initNetwork(first);
	}

	@Override
	protected void closeNetwork() {
		EndpointManager.reset();
		messageThreads.set(DEFAULT_MESSAGE_THREADS);
		NetworkConfig.setStandard(null);
		super.closeNetwork();
	}

	/**
	 * Create new standard network configuration for testing.
	 * 
	 * @return fresh standard network configurations. Changes are visible to
	 *         other usage of the standard configuration.
	 * @see NetworkConfig#getStandard()
	 */
	public NetworkConfig createStandardTestConfig() {
		NetworkConfig config = createTestConfig();
		NetworkConfig.setStandard(config);
		return config;
	}

	/**
	 * Get standard network configuration for testing.
	 * 
	 * @return standard network configurations. Changes are visible to other
	 *         usage of the standard configuration.
	 * @see NetworkConfig#getStandard()
	 */
	public NetworkConfig getStandardTestConfig() {
		ensureThisRuleIsActive();
		return NetworkConfig.getStandard();
	}

	/**
	 * Create new network configuration for testing.
	 * 
	 * @return network configurations. Detached from the standard network
	 *         configuration.
	 */
	public NetworkConfig createTestConfig() {
		ensureThisRuleIsActive();
		int threads = messageThreads.get();
		NetworkConfig config = new NetworkConfig();
		config.setInt(NetworkConfig.Keys.NETWORK_STAGE_RECEIVER_THREAD_COUNT, threads);
		config.setInt(NetworkConfig.Keys.NETWORK_STAGE_SENDER_THREAD_COUNT, threads);
		return config;
	}
}
