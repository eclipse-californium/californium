/*******************************************************************************
 * Copyright (c) 2022 RISE and others.
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
 * Rikard Höglund (RISE)
 *    
 ******************************************************************************/
package org.eclipse.californium.oscore;

import org.eclipse.californium.core.network.Outbox;
import org.eclipse.californium.core.network.stack.BaseCoapStack;
import org.eclipse.californium.core.network.stack.BlockwiseLayer;
import org.eclipse.californium.core.network.stack.Layer;
import org.eclipse.californium.core.network.stack.TcpAdaptionLayer;
import org.eclipse.californium.core.network.stack.TcpExchangeCleanupLayer;
import org.eclipse.californium.core.network.stack.TcpObserveLayer;
import org.eclipse.californium.elements.EndpointContextMatcher;
import org.eclipse.californium.elements.config.Configuration;

/**
 * TCP CoAP stack supporting OSCORE.
 * 
 * Extends the BaseCoapStack and adds the ObjectSecurityLayer.
 *
 */
public class OSCoreTcpStack extends BaseCoapStack {

	/**
	 * Creates a new OSCORE-enabled stack using TCP as the transport.
	 * 
	 * @param tag logging tag
	 * @param config The configuration values to use.
	 * @param matchingStrategy endpoint context matcher to relate responses with
	 *            requests
	 * @param outbox The adapter for submitting outbound messages to the
	 *            transport.
	 * @param ctxDb context DB.
	 * @since 3.5
	 */
	public OSCoreTcpStack(String tag, Configuration config, EndpointContextMatcher matchingStrategy, Outbox outbox,
			OSCoreCtxDB ctxDb) {
		super(outbox);

		Layer layers[] = new Layer[] { new ObjectSecurityContextLayer(ctxDb), new TcpExchangeCleanupLayer(),
				new TcpObserveLayer(config), new BlockwiseLayer(tag, true, config, matchingStrategy),
				new TcpAdaptionLayer(), new ObjectSecurityLayer(ctxDb) };

		setLayers(layers);

		// make sure the endpoint sets a MessageDeliverer
	}
}
