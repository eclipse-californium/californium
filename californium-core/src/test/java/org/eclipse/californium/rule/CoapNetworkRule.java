/*******************************************************************************
 * Copyright (c) 2017 Bosch Software Innovations GmbH and others.
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
 *    Bosch Software Innovations - initial implementation
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - add support for subclassing
 ******************************************************************************/
package org.eclipse.californium.rule;

import org.eclipse.californium.core.coap.Message;
import org.eclipse.californium.core.config.CoapConfig;
import org.eclipse.californium.core.network.EndpointManager;
import org.eclipse.californium.core.network.serialization.DataParser;
import org.eclipse.californium.core.network.serialization.UdpDataParser;
import org.eclipse.californium.elements.config.Configuration;
import org.eclipse.californium.elements.rule.NetworkRule;
import org.eclipse.californium.elements.util.DatagramFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CoAP network rules for junit test using datagram sockets.
 * 
 * Though {@link EndpointManager} depend on some
 * internal state, this rule manages these states by setup and cleanup the
 * values.
 *
 * The rule is intended to be mainly used as {@code &#64;ClassRule}.
 * 
 * <pre>
 * public class AbcNetworkTest {
 *    &#64;ClassRule
 *    public static CoapNetworkRule network = new CoapNetworkRule(Mode.DIRECT, Mode.NATIVE);
 *    ...
 * </pre>
 */
public class CoapNetworkRule extends NetworkRule {

	public static final Logger LOGGER = LoggerFactory.getLogger(CoapNetworkRule.class);
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
	 * Create rule supporting provided modes.
	 * 
	 * @param modes
	 *            supported datagram socket implementation modes.
	 */
	public CoapNetworkRule(Mode... modes) {
		this(FORMATTER, modes);
	}

	/**
	 * Create rule supporting provided modes.
	 * 
	 * Intended to be called from subclasses.
	 * 
	 * @param formatter datagram formatter to be used
	 * @param modes supported datagram socket implementation modes.
	 */
	protected CoapNetworkRule(DatagramFormatter formatter, Mode... modes) {
		super(formatter, modes);
	}

	@Override
	public CoapNetworkRule setDelay(int delayInMillis) {
		return (CoapNetworkRule) super.setDelay(delayInMillis);
	}

	@Override
	public CoapNetworkRule setMessageThreads(int threads) {
		return (CoapNetworkRule) super.setMessageThreads(threads);
	}
	
	@Override
	protected void initNetwork(boolean first) {
		if (first) {
			EndpointManager.reset();
		}
		super.initNetwork(first);
	}

	@Override
	protected void closeNetwork() {
		EndpointManager.reset();
		super.closeNetwork();
	}

	/**
	 * Create new configuration for testing.
	 * 
	 * @return configurations. Detached from the standard
	 *         configuration.
	 */
	@Override
	public Configuration createTestConfig() {
		CoapConfig.register();
		Configuration config = super.createTestConfig();
		int threads = messageThreads.get();
		config.set(CoapConfig.PROTOCOL_STAGE_THREAD_COUNT, threads);
		return config;
	}
}
