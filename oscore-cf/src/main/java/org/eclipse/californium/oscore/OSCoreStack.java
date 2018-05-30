/*******************************************************************************
 * Copyright (c) 2018 RISE SICS and others.
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
 *    Joakim Brorsson
 *    Ludwig Seitz (RISE SICS)
 *    Tobias Andersson (RISE SICS)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.config.NetworkConfig;
import org.eclipse.californium.core.network.stack.BaseCoapStack;
import org.eclipse.californium.core.network.stack.BlockwiseLayer;
import org.eclipse.californium.core.network.stack.CongestionControlLayer;
import org.eclipse.californium.core.network.stack.ExchangeCleanupLayer;
import org.eclipse.californium.core.network.stack.Layer;
import org.eclipse.californium.core.network.stack.ObserveLayer;
import org.eclipse.californium.core.network.stack.ReliabilityLayer;

/**
 * 
 * Extends the BaseCoapStack and adds the ObjectSecurityLayer.
 *
 */
public class OSCoreStack extends BaseCoapStack {

	/**
	 * The logger
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(OSCoreStack.class.getName());

	/**
	 * Creates a new stack for UDP as the transport.
	 * 
	 * @param config The configuration values to use.
	 * @param outbox The adapter for submitting outbound messages to the
	 *            transport.
	 */
	public OSCoreStack(final NetworkConfig config, final Outbox outbox) {
		super(outbox);
		ReliabilityLayer reliabilityLayer;
		if (config.getBoolean(NetworkConfig.Keys.USE_CONGESTION_CONTROL)) {
			reliabilityLayer = CongestionControlLayer.newImplementation(config);
			LOGGER.info("Enabling congestion control: {0}", reliabilityLayer.getClass().getSimpleName());
		} else {
			reliabilityLayer = new ReliabilityLayer(config);
		}

		Layer layers[] = new Layer[] { new ExchangeCleanupLayer(), new ObserveLayer(config), new BlockwiseLayer(config),
				reliabilityLayer, new ObjectSecurityLayer(), };
		setLayers(layers);
	}
}
