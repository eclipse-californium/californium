/*******************************************************************************
 * Copyright (c) 2015, 2016 Institute for Pervasive Computing, ETH Zurich and others.
 * <p>
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * <p>
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.html.
 * <p>
 * Contributors:
 *    Matthias Kovatsch - creator and main architect
 *    Martin Lanter - architect and re-implementation
 *    Dominique Im Obersteg - parsers and initial implementation
 *    Daniel Pauli - parsers and initial implementation
 *    Kai Hudalla - logging
 *    Kai Hudalla (Bosch Software Innovations GmbH) - use Logger's message formatting instead of
 *                                                    explicit String concatenation
 *    Achim Kraus (Bosch Software Innovations GmbH) - move common function to BaseCoapStack
 ******************************************************************************/
package org.eclipse.californium.core.network.stack;

import java.util.logging.Level;
import java.util.logging.Logger;

import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.server.MessageDeliverer;
import org.eclipse.californium.elements.Connector;

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
	private final static Logger LOGGER = Logger.getLogger(CoapUdpStack.class.getCanonicalName());

	/**
	 * Creates a new stack for UDP as the transport.
	 * 
	 * @param config The configuration values to use.
	 * @param outbox The adapter for submitting outbound messages to the transport.
	 */
	public CoapUdpStack(final NetworkConfig config, final Outbox outbox) {
		super(outbox);

		ReliabilityLayer reliabilityLayer;
		if (config.getBoolean(NetworkConfig.Keys.USE_CONGESTION_CONTROL)) {
			reliabilityLayer = CongestionControlLayer.newImplementation(config);
			LOGGER.log(Level.CONFIG, "Enabling congestion control: {0}", reliabilityLayer.getClass().getSimpleName());
		} else {
			reliabilityLayer = new ReliabilityLayer(config);
		}

		Layer layers[] = new Layer[] {
				new ExchangeCleanupLayer(),
				new ObserveLayer(config),
				new BlockwiseLayer(config),
				reliabilityLayer };

		setLayers(layers);

		// make sure the endpoint sets a MessageDeliverer
	}
}
