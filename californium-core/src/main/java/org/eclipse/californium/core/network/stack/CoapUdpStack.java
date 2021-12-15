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

import org.eclipse.californium.core.network.ExtendedCoapStackFactory;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.Connector;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.config.Configuration;

/**
 * The CoAPStack builds up the stack of CoAP layers that process the CoAP
 * protocol.
 * <p>
 * The complete process for incoming and outgoing messages is visualized below.
 * The class {@link CoapStack} builds up the part between the Stack Top and
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
 * 
 * Note: since 3.1 the create-layer methods have been deprecated. If your usage
 * requires to have custom layers, please implement a own {@link CoapStack} and
 * use the {@link ExtendedCoapStackFactory} to provide instances of that custom
 * implementation.
 */
public class CoapUdpStack extends BaseCoapStack {

	/**
	 * Creates a new stack for UDP as the transport.
	 * 
	 * Note: in order to match blockwise follow up requests, this constructor is
	 * required. It doesn't longer call the create-layer functions. If that is
	 * required, please use a own custom implementation of the {@link CoapStack}
	 * and the {@link ExtendedCoapStackFactory} to provide instances of that
	 * custom implementation.
	 * 
	 * @param tag logging tag
	 * @param config The configuration values to use.
	 * @param matchingStrategy endpoint context matcher to relate responses with
	 *            requests
	 * @param outbox The adapter for submitting outbound messages to the
	 *            transport.
	 * @since 3.1
	 */
	public CoapUdpStack(String tag, Configuration config, EndpointContextMatcher matchingStrategy, Outbox outbox) {
		super(outbox);
		Layer[] layers = new Layer[] { new ExchangeCleanupLayer(config), new ObserveLayer(config),
				new BlockwiseLayer(tag, false, config, matchingStrategy),
				CongestionControlLayer.newImplementation(tag, config) };
		setLayers(layers);
	}

	/**
	 * Creates a new stack for UDP as the transport.
	 * 
	 * @param tag logging tag
	 * @param config The configuration values to use.
	 * @param outbox The adapter for submitting outbound messages to the
	 *            transport.
	 * @deprecated use
	 *             {@link #CoapUdpStack(String, Configuration, EndpointContextMatcher, Outbox)}
	 *             instead
	 * @since 3.0 (logging tag added and changed parameter to Configuration)
	 */
	public CoapUdpStack(String tag, Configuration config, Outbox outbox) {
		super(outbox);
		Layer layers[] = new Layer[] { createExchangeCleanupLayer(config), createObserveLayer(config),
				createBlockwiseLayer(tag, config), createReliabilityLayer(tag, config) };

		setLayers(layers);
	}

	/**
	 * Create exchange cleanup layer.
	 * 
	 * @param config configuration
	 * @return exchange cleanup layer
	 * @deprecated use a custom implementation of the {@link CoapStack} and the
	 *             {@link ExtendedCoapStackFactory} instead.
	 */
	protected Layer createExchangeCleanupLayer(Configuration config) {
		return new ExchangeCleanupLayer(config);
	}

	/**
	 * Create observe layer.
	 * 
	 * @param config configuration
	 * @return observe layer
	 * @deprecated use a custom implementation of the {@link CoapStack} and the
	 *             {@link ExtendedCoapStackFactory} instead.
	 */
	protected Layer createObserveLayer(Configuration config) {
		return new ObserveLayer(config);
	}

	/**
	 * Create blockwise layer.
	 * 
	 * @param tag logging tag
	 * @param config configuration
	 * @return blockwise layer
	 * @deprecated use a custom implementation of the {@link CoapStack} and the
	 *             {@link ExtendedCoapStackFactory} instead.
	 */
	protected Layer createBlockwiseLayer(String tag, Configuration config) {
		return new BlockwiseLayer(tag, false, config);
	}

	/**
	 * Create reliability layer.
	 * 
	 * @param tag logging tag
	 * @param config configuration
	 * @return reliability layer
	 * @deprecated use a custom implementation of the {@link CoapStack} and the
	 *             {@link ExtendedCoapStackFactory} instead.
	 */
	protected Layer createReliabilityLayer(String tag, Configuration config) {
		return CongestionControlLayer.newImplementation(tag, config);
	}
}
