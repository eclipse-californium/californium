/*******************************************************************************
 * Copyright (c) 2015, 2017 Institute for Pervasive Computing, ETH Zurich and others.
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
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Achim Kraus (Bosch Software Innovations GmbH) - move common function to BaseCoapStack
 *    Bosch Software Innovations GmbH - migrate to SLF4J
 *    Achim Kraus (Bosch Software Innovations GmbH) - add multicast support.
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContextMatcher;

/**
 * The CoAPStack builds up the stack of CoAP layers that process the CoAP
 * protocol.
 * <p>
 * The complete process for incoming and outgoing messages is visualized below.
 * The class <code>CoapStack</code> builds up the part between the Stack Top and
 * Bottom.
 * <hr><blockquote><pre>
 * +--------------------------+
 * | {@link MessageDeliverer}         |
 * +--------------A-----------+
 *                A
 *              * A
 * +------------+-A-----------+
 * |       CoAPEndpoint       |
 * |            v A           |
 * |            v A           |
 * | +----------v-+---------+ |
 * | | Stack Top            | |
 * | +----------------------+ |
 * | | {@link ExchangeCleanupLayer} | |
 * | +----------------------+ |
 * | | {@link ObserveLayer}         | |
 * | +----------------------+ |
 * | | {@link BlockwiseLayer}       | |
 * | +----------------------+ |
 * | | {@link ReliabilityLayer}     | |
 * | +----------------------+ |
 * | | Stack Bottom         | |
 * | +----------+-A---------+ |
 * |            v A           |
 * |          Matcher         |
 * |            v A           |
 * |        Interceptor       |
 * |            v A           |
 * +------------v-A-----------+
 *              v A 
 *              v A 
 * +------------v-+-----------+
 * | {@link Connector}                |
 * +--------------------------+
 * </pre></blockquote><hr>
 */
public class CoapUdpStack extends BaseCoapStack {

	/** The LOGGER. */
	private final static Logger LOGGER = LoggerFactory.getLogger(CoapStack.class);

	/**
	 * Creates a new stack for UDP as the transport.
	 * 
	 * @param config The configuration values to use.
	 * @param matchingStrategy endpoint context matcher to relate responses with
	 *            requests
	 * @param outbox The adapter for submitting outbound messages to the transport.
	 * @since 3.1 (back-ported to 2.7.0)
	 */
	public CoapUdpStack(final NetworkConfig config, final EndpointContextMatcher matchingStrategy, final Outbox outbox) {
		super(outbox);
		ReliabilityLayer reliabilityLayer;
		if (config.getBoolean(NetworkConfig.Keys.USE_CONGESTION_CONTROL) == true) {
			reliabilityLayer = CongestionControlLayer.newImplementation(config);
			LOGGER.info("Enabling congestion control: {}", reliabilityLayer.getClass().getSimpleName());
		} else {
			reliabilityLayer = new ReliabilityLayer(config);
		}
		Layer layers[] = new Layer[] {
				new ExchangeCleanupLayer(config),
				new ObserveLayer(config),
				new BlockwiseLayer(config, matchingStrategy),
				reliabilityLayer};

		setLayers(layers);
	}

	/**
	 * Creates a new stack for UDP as the transport.
	 * 
	 * @param config The configuration values to use.
	 * @param outbox The adapter for submitting outbound messages to the transport.
	 * @deprecated use {@link #CoapUdpStack(NetworkConfig, EndpointContextMatcher, Outbox)} instead.
	 */
	public CoapUdpStack(final NetworkConfig config, final Outbox outbox) {
		super(outbox);
		Layer layers[] = new Layer[] {
				createExchangeCleanupLayer(config),
				createObserveLayer(config),
				createBlockwiseLayer(config),
				createReliabilityLayer(config)};

		setLayers(layers);
	}

	@Deprecated
	protected Layer createExchangeCleanupLayer(NetworkConfig config) {
		return new ExchangeCleanupLayer(config);
	}

	@Deprecated
	protected Layer createObserveLayer(NetworkConfig config) {
		return new ObserveLayer(config);
	}

	@Deprecated
	protected Layer createBlockwiseLayer(NetworkConfig config) {
		return new BlockwiseLayer(config, null);
	}

	@Deprecated
	protected Layer createReliabilityLayer(NetworkConfig config) {
		ReliabilityLayer reliabilityLayer;
		if (config.getBoolean(NetworkConfig.Keys.USE_CONGESTION_CONTROL) == true) {
			reliabilityLayer = CongestionControlLayer.newImplementation(config);
			LOGGER.info("Enabling congestion control: {}", reliabilityLayer.getClass().getSimpleName());
		} else {
			reliabilityLayer = new ReliabilityLayer(config);
		}
		return reliabilityLayer;
	}
}
